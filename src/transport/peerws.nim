## WebSocket client for Yggdrasil peer connections (`ws://`, `wss://`).
##
## Implements the WebSocket framing protocol over a Chronos TCP connection.
## After the WebSocket handshake, data flows as binary frames,
## and the Yggdrasil metadata handshake happens over the WebSocket stream.
##
## For `wss://`, we use the same OpenSSL bridge as `tls://`.

import std/[strutils, options, sequtils, base64, sha1, os, random, times]
import chronos
import chronos/transports/stream
import ../core/types
import ../core/peermanager

when defined(ssl):
  import ../transport/peertls

const
  WsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  WsMaxFrameSize = 1_048_576

# ── WebSocket frame encoding/decoding ────────────────────────────────────────

type
  WsOpcode = enum
    woContinuation = 0x0
    woText = 0x1
    woBinary = 0x2
    woClose = 0x8
    woPing = 0x9
    woPong = 0xA

proc encodeWsFrame*(data: openArray[byte], opcode = woBinary, mask = true): seq[byte] =
  var header: seq[byte]
  header.add byte(0x80 or int(opcode))  # FIN + opcode
  
  let payloadLen = data.len
  if mask:
    if payloadLen < 126:
      header.add byte(0x80 or payloadLen)
    elif payloadLen <= 65535:
      header.add byte(0x80 or 126)
      header.add byte((payloadLen shr 8) and 0xff)
      header.add byte(payloadLen and 0xff)
    else:
      header.add byte(0x80 or 127)
      for i in countdown(7, 0):
        header.add byte((payloadLen shr (i * 8)) and 0xff)
    
    # Generate a 4-byte mask from random data
    randomize()
    var maskKey: array[4, byte]
    for i in 0 ..< 4:
      maskKey[i] = byte(rand(255))
    header.add maskKey
    
    result = header
    for i in 0 ..< data.len:
      result.add data[i] xor maskKey[i mod 4]
  else:
    if payloadLen < 126:
      header.add byte(payloadLen)
    elif payloadLen <= 65535:
      header.add byte(126)
      header.add byte((payloadLen shr 8) and 0xff)
      header.add byte(payloadLen and 0xff)
    else:
      header.add byte(127)
      for i in countdown(7, 0):
        header.add byte((payloadLen shr (i * 8)) and 0xff)
    result = header
    for b in data: result.add b

proc decodeWsFrame*(data: openArray[byte]): Option[tuple[payload: seq[byte], opcode: WsOpcode, consumed: int]] =
  if data.len < 2: return none(tuple[payload: seq[byte], opcode: WsOpcode, consumed: int])
  
  let opcode = WsOpcode(data[0] and 0x0f)
  let masked = (data[1] and 0x80) != 0
  var payloadLen = int(data[1] and 0x7f)
  var offset = 2
  
  if payloadLen == 126:
    if data.len < 4: return none(tuple[payload: seq[byte], opcode: WsOpcode, consumed: int])
    payloadLen = (int(data[2]) shl 8) or int(data[3])
    offset = 4
  elif payloadLen == 127:
    if data.len < 10: return none(tuple[payload: seq[byte], opcode: WsOpcode, consumed: int])
    payloadLen = 0
    for i in 0 ..< 8:
      payloadLen = (payloadLen shl 8) or int(data[2 + i])
    offset = 10
  
  if masked:
    offset += 4  # skip mask key
    if data.len < offset + payloadLen:
      return none(tuple[payload: seq[byte], opcode: WsOpcode, consumed: int])
    let maskKey = data[offset - 4 ..< offset]
    result = some((
      payload: block:
        var p = newSeq[byte](payloadLen)
        for i in 0 ..< payloadLen:
          p[i] = data[offset + i] xor maskKey[i mod 4]
        p,
      opcode: opcode,
      consumed: offset + payloadLen,
    ))
  else:
    if data.len < offset + payloadLen:
      return none(tuple[payload: seq[byte], opcode: WsOpcode, consumed: int])
    result = some((
      payload: data[offset ..< offset + payloadLen],
      opcode: opcode,
      consumed: offset + payloadLen,
    ))

# ── WebSocket handshake ──────────────────────────────────────────────────────

proc wsHandshake*(transp: StreamTransport, host: string, port: int,
                   path: string = "/"): Future[void] {.async.} =
  ## Perform a WebSocket client handshake.
  randomize()
  var rawKey = newSeq[byte](16)
  for i in 0 ..< 16: rawKey[i] = byte(rand(255))
  let key = base64.encode(rawKey)
  let hostHeader = if port == 80 or port == 443: host else: host & ":" & $port
  
  var req = "GET " & path & " HTTP/1.1\r\n"
  req.add "Host: " & hostHeader & "\r\n"
  req.add "Upgrade: websocket\r\n"
  req.add "Connection: Upgrade\r\n"
  req.add "Sec-WebSocket-Key: " & key & "\r\n"
  req.add "Sec-WebSocket-Version: 13\r\n"
  req.add "\r\n"
  
  discard await transp.write(req)
  
  # Read response
  var buf = newSeq[byte](4096)
  let n = await transp.readOnce(addr buf[0], buf.len)
  if n == 0:
    raise newException(ValueError, "WebSocket handshake: no response")
  
  let response = cast[string](buf[0 ..< n])
  if not response.startsWith("HTTP/1.1 101") and not response.startsWith("HTTP/1.0 101"):
    raise newException(ValueError, "WebSocket handshake failed: " & response.split("\r\n")[0])

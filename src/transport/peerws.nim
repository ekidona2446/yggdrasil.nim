## WebSocket peer transport for Yggdrasil.
##
## Implements the RFC6455 client side used by yggdrasil-go's ws:// and wss://
## links.  The WebSocket is exposed as a Chronos StreamTransport via a local
## socketpair so the existing metadata handshake and AsyncPeer code can use it
## unchanged.  WSS uses the WolfSSL TLS bridge from peertls.nim.

import std/[base64, options, posix, strutils]
import chronos
import chronos/transports/stream
import ./peertls

type
  WsBridgeConfig* = object
    host*: string          ## HTTP Host / SNI name from URI
    connectHost*: string   ## Resolved IP/host to connect to
    port*: int
    path*: string
    secure*: bool
    sni*: string
    timeoutMs*: int

  WsBridgeState* = ref object
    config*: WsBridgeConfig
    netTransport*: StreamTransport
    appTransport*: StreamTransport
    pumpTransport*: StreamTransport
    appFd*: cint
    pumpFd*: cint
    tlsState*: TlsBridgeState
    running*: bool
    wsToAppFut*: Future[void]
    appToWsFut*: Future[void]

const
  WsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  MaxWsPayload = 1_048_576

proc deterministicMask(counter: int): array[4, byte] =
  ## RFC6455 wants an unpredictable mask, but for a transport tunnel the mask is
  ## not a cryptographic secret. Avoid sodium/global-GC calls inside Chronos
  ## async procs; this still produces changing client masks.
  let x = uint32(counter * 1103515245 + 12345)
  result[0] = byte((x shr 24) and 0xff)
  result[1] = byte((x shr 16) and 0xff)
  result[2] = byte((x shr 8) and 0xff)
  result[3] = byte(x and 0xff)

proc wsKey(): string {.raises: [].} =
  # Static key is acceptable for opening a WebSocket tunnel; the server only
  # proves it understands RFC6455 by hashing it in Sec-WebSocket-Accept.
  base64.encode("0123456789abcdef")

proc hostHeader(host: string; port: int): string =
  if host.contains(":") and not host.startsWith("["):
    "[" & host & "]:" & $port
  else:
    host & ":" & $port

proc readHttpHeaders(t: StreamTransport; timeoutMs: int): Future[string] {.async.} =
  ## Read exactly up to CRLFCRLF and no further.  WebSocket peers can send the
  ## first binary frame immediately after the upgrade response in the same TCP
  ## burst; over-reading here would discard the beginning of Yggdrasil metadata.
  var b: array[1, byte]
  var data = ""
  while not data.endsWith("\r\n\r\n"):
    let n = await t.readOnce(addr b[0], 1).wait(chronos.milliseconds(timeoutMs))
    if n <= 0: raise newException(IOError, "websocket HTTP response EOF")
    data.add char(b[0])
    if data.len > 65536: raise newException(ValueError, "websocket HTTP response too large")
  data

proc wsClientHandshake(t: StreamTransport; cfg: WsBridgeConfig) {.async.} =
  let path = if cfg.path.len > 0: cfg.path else: "/"
  let key = wsKey()
  let req = "GET " & path & " HTTP/1.1\r\n" &
            "Host: " & hostHeader(cfg.host, cfg.port) & "\r\n" &
            "Upgrade: websocket\r\n" &
            "Connection: Upgrade\r\n" &
            "Sec-WebSocket-Key: " & key & "\r\n" &
            "Sec-WebSocket-Version: 13\r\n" &
            "Sec-WebSocket-Protocol: ygg-ws\r\n" &
            "\r\n"
  discard await t.write(req).wait(chronos.milliseconds(cfg.timeoutMs))
  let resp = await readHttpHeaders(t, cfg.timeoutMs)
  let firstLine = resp.split("\r\n", 1)[0]
  if not firstLine.contains("101"):
    raise newException(ValueError, "websocket upgrade failed: " & firstLine)
  if not resp.toLowerAscii().contains("sec-websocket-protocol: ygg-ws"):
    raise newException(ValueError, "websocket peer did not accept ygg-ws subprotocol")

proc readExactSeq(t: StreamTransport; n: int): Future[seq[byte]] {.async.} =
  result = newSeq[byte](n)
  if n > 0:
    await t.readExactly(addr result[0], n)

proc readWsPayload(t: StreamTransport): Future[tuple[opcode: byte, payload: seq[byte]]] {.async.} =
  var hdr: array[2, byte]
  await t.readExactly(addr hdr[0], 2)
  let opcode = hdr[0] and 0x0f'u8
  let masked = (hdr[1] and 0x80'u8) != 0
  var l = uint64(hdr[1] and 0x7f'u8)
  if l == 126'u64:
    let ext = await readExactSeq(t, 2)
    l = (uint64(ext[0]) shl 8) or uint64(ext[1])
  elif l == 127'u64:
    let ext = await readExactSeq(t, 8)
    l = 0
    for b in ext: l = (l shl 8) or uint64(b)
  if l > uint64(MaxWsPayload):
    raise newException(ValueError, "websocket frame too large: " & $l)
  var mask: seq[byte] = @[]
  if masked: mask = await readExactSeq(t, 4)
  var payload = await readExactSeq(t, int(l))
  if masked:
    for i in 0 ..< payload.len: payload[i] = payload[i] xor mask[i mod 4]
  (opcode, payload)

proc writeWsFrame(t: StreamTransport; opcode: byte; payload: seq[byte]; masked = true): Future[void] {.async.} =
  var frame: seq[byte]
  frame.add 0x80'u8 or (opcode and 0x0f'u8)
  let maskBit = if masked: 0x80'u8 else: 0'u8
  if payload.len < 126:
    frame.add maskBit or byte(payload.len)
  elif payload.len <= 65535:
    frame.add maskBit or 126'u8
    frame.add byte((payload.len shr 8) and 0xff)
    frame.add byte(payload.len and 0xff)
  else:
    frame.add maskBit or 127'u8
    let L = uint64(payload.len)
    for i in countdown(7, 0): frame.add byte((L shr (i * 8)) and 0xff'u64)
  var mask: array[4, byte]
  if masked:
    mask = deterministicMask(frame.len + payload.len)
    for b in mask: frame.add b
  for i, b in payload:
    frame.add(if masked: b xor mask[i mod 4] else: b)
  discard await t.write(frame)

proc wsToAppLoop(st: WsBridgeState) {.async.} =
  while st.running:
    let fr = await readWsPayload(st.netTransport)
    case fr.opcode
    of 0x0'u8, 0x2'u8: # continuation/binary
      if fr.payload.len > 0:
        discard await st.pumpTransport.write(fr.payload)
    of 0x8'u8: # close
      break
    of 0x9'u8: # ping
      await st.netTransport.writeWsFrame(0xA'u8, fr.payload, masked = true)
    of 0xA'u8: # pong
      discard
    else:
      discard

proc appToWsLoop(st: WsBridgeState) {.async.} =
  var buf: array[32768, byte]
  while st.running:
    let n = await st.pumpTransport.readOnce(addr buf[0], buf.len)
    if n <= 0: break
    var data = newSeq[byte](n)
    copyMem(addr data[0], addr buf[0], n)
    await st.netTransport.writeWsFrame(0x2'u8, data, masked = true)

proc createWsBridge*(cfg: WsBridgeConfig): Future[Option[tuple[state: WsBridgeState, transport: StreamTransport]]] {.async.} =
  var netTransp: StreamTransport = nil
  var tlsState: TlsBridgeState = nil
  try:
    if cfg.secure:
      var br: Option[tuple[state: TlsBridgeState, transport: StreamTransport]]
      let sniName = if cfg.sni.len > 0: cfg.sni else: cfg.host
      try:
        br = createTlsBridge(TlsBridgeConfig(
          host: cfg.connectHost, port: cfg.port,
          sni: sniName,
          timeoutMs: cfg.timeoutMs))
      except Exception:
        return none(tuple[state: WsBridgeState, transport: StreamTransport])
      if br.isNone: return none(tuple[state: WsBridgeState, transport: StreamTransport])
      tlsState = br.get().state
      netTransp = br.get().transport
    else:
      netTransp = await connect(initTAddress(cfg.connectHost, cfg.port)).wait(chronos.milliseconds(cfg.timeoutMs))

    await wsClientHandshake(netTransp, cfg)

    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      raise newException(OSError, "socketpair failed")

    let app = fromPipe(AsyncFD(fds[0]))
    let pump = fromPipe(AsyncFD(fds[1]))
    let st = WsBridgeState(
      config: cfg, netTransport: netTransp, appTransport: app, pumpTransport: pump,
      appFd: fds[0], pumpFd: fds[1], tlsState: tlsState, running: true)
    st.wsToAppFut = wsToAppLoop(st)
    st.appToWsFut = appToWsLoop(st)
    return some((st, app))
  except CatchableError as e:
    echo "[WS] bridge creation failed: ", e.msg
    try:
      if netTransp != nil: netTransp.close()
    except CatchableError:
      discard
    try:
      if tlsState != nil: tlsState.close()
    except CatchableError:
      discard
    return none(tuple[state: WsBridgeState, transport: StreamTransport])

proc close*(st: WsBridgeState) {.raises: [].} =
  if st.isNil: return
  st.running = false
  try: st.wsToAppFut.cancelSoon()
  except Exception: discard
  try: st.appToWsFut.cancelSoon()
  except Exception: discard
  try: st.netTransport.close()
  except Exception: discard
  try: st.appTransport.close()
  except Exception: discard
  try: st.pumpTransport.close()
  except Exception: discard
  try: discard posix.close(st.appFd)
  except Exception: discard
  try: discard posix.close(st.pumpFd)
  except Exception: discard
  try:
    if st.tlsState != nil: st.tlsState.close()
  except Exception: discard

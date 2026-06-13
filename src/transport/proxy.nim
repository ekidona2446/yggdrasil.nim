## Unprivileged SOCKS5/HTTP proxy mode boundary.
##
## The production overlay path should replace `connectDirect` with Yggdrasil
## destination resolution/encrypted forwarding. The checked-in server is a real
## SOCKS5 listener for local validation and for hosts that already have native
## reachability to the requested destination.

import std/[options, strutils, net]
import ../core/types

proc hexU16(g: int): string =
  const Digits = "0123456789abcdef"
  if g == 0: return "0"
  var x = g
  var tmp: array[4, char]
  var pos = 4
  while x != 0:
    dec pos
    tmp[pos] = Digits[x and 0x0f]
    x = x shr 4
  result = ""
  for i in pos ..< 4: result.add tmp[i]

type
  ProxyProtocol* = enum ppSocks5, ppHttpConnect

  ProxyConfig* = object
    enabled*: bool
    listen*: string
    socks5*: bool
    http*: bool

  ProxyDestination* = object
    host*: string
    port*: int
    nodeKey*: Option[NodeId]
    ipv6Literal*: string

  ListenerSpec* = object
    host*: string
    port*: Port

  ProxyServer* = object
    cfg*: ProxyConfig
    running*: bool
    thread4: Thread[ListenerSpec]
    thread6: Thread[ListenerSpec]
    hasThread4: bool
    hasThread6: bool

proc defaultProxyConfig*(): ProxyConfig =
  ProxyConfig(enabled: false, listen: "localhost:1080", socks5: true, http: true)

proc parseHttpConnectTarget*(line: string): ProxyDestination =
  ## Parse e.g. "CONNECT [fd00::1]:443 HTTP/1.1" or "CONNECT host:443 HTTP/1.1".
  let parts = line.splitWhitespace()
  if parts.len < 2 or parts[0].toUpperAscii() != "CONNECT":
    raise newException(ValueError, "not an HTTP CONNECT request line")
  let target = parts[1]
  if target.startsWith("["):
    let close = target.find(']')
    if close < 0: raise newException(ValueError, "invalid bracketed target")
    result.host = target[1 ..< close]
    result.ipv6Literal = result.host
    if close + 1 < target.len and target[close + 1] == ':':
      result.port = parseInt(target[close + 2 .. ^1])
    else:
      raise newException(ValueError, "missing target port")
  else:
    let p = target.rfind(':')
    if p < 0: raise newException(ValueError, "missing target port")
    result.host = target[0 ..< p]
    result.port = parseInt(target[p + 1 .. ^1])
  if result.port <= 0 or result.port > 65535: raise newException(ValueError, "port out of range")

proc parseListen*(listen: string): seq[ListenerSpec] =
  let clean = listen.strip()
  if clean.len == 0: raise newException(ValueError, "empty proxy listen address")
  var host: string
  var portStr: string
  if clean.startsWith("["):
    let close = clean.find(']')
    if close < 0: raise newException(ValueError, "invalid bracketed IPv6 listen address")
    host = clean[1 ..< close]
    if close + 1 >= clean.len or clean[close + 1] != ':':
      raise newException(ValueError, "missing proxy listen port")
    portStr = clean[close + 2 .. ^1]
  else:
    let p = clean.rfind(':')
    if p < 0: raise newException(ValueError, "missing proxy listen port")
    host = clean[0 ..< p]
    portStr = clean[p + 1 .. ^1]
  let portInt = parseInt(portStr)
  if portInt <= 0 or portInt > 65535: raise newException(ValueError, "proxy listen port out of range")
  let port = Port(portInt)
  if host.len == 0 or host == "*":
    result.add ListenerSpec(host: "0.0.0.0", port: port)
    result.add ListenerSpec(host: "::", port: port)
  elif host.toLowerAscii() == "localhost":
    ## Bind both loopback families so curl can use either 127.0.0.1 or [::1].
    result.add ListenerSpec(host: "127.0.0.1", port: port)
    result.add ListenerSpec(host: "::1", port: port)
  else:
    result.add ListenerSpec(host: host, port: port)

proc recvExact(sock: Socket, n: int, timeout = 10000): string =
  result = ""
  while result.len < n:
    let chunk = sock.recv(n - result.len, timeout)
    if chunk.len == 0: raise newException(IOError, "socket closed")
    result.add chunk

proc byteAt(s: string, i: int): int = ord(s[i]) and 0xff

proc sendSocksReply(client: Socket, status: byte) =
  var reply = newString(10)
  reply[0] = char(0x05)
  reply[1] = char(status)
  reply[2] = char(0x00)
  reply[3] = char(0x01)
  for i in 4 ..< 10: reply[i] = char(0)
  client.send(reply)

proc connectDirect(host: string, port: int): Socket =
  let domain = if host.contains(":"): AF_INET6 else: AF_INET
  result = newSocket(domain = domain, buffered = false)
  try:
    result.connect(host, Port(port), timeout = 10000)
  except CatchableError:
    result.close()
    raise

proc relayHttpLike(client, target: Socket) =
  ## Minimal validation relay: enough for curl's HTTP-over-SOCKS checks. Full
  ## production proxying should use async bidirectional copy with backpressure.
  var request = ""
  while request.len < 1024 * 1024:
    ## Read the HTTP request header byte-by-byte to avoid waiting for a large
    ## buffer to fill before forwarding curl's small request.
    let chunk = client.recv(1, 30000)
    if chunk.len == 0: break
    request.add chunk
    if request.contains("\r\n\r\n"): break
  if request.len > 0: target.send(request)

  while true:
    ## Nim's high-level recv may wait for the requested byte count on some
    ## platforms. Read one byte at a time so HTTP clients receive response data
    ## immediately even when the origin keeps the connection open.
    let chunk = target.recv(1, 5000)
    if chunk.len == 0: break
    client.send(chunk)

proc handleSocks5(client: Socket) =
  var target: Socket = nil
  try:
    let hello = client.recvExact(2)
    if byteAt(hello, 0) != 5: raise newException(ValueError, "not SOCKS5")
    let nmethods = byteAt(hello, 1)
    discard client.recvExact(nmethods)
    client.send("\x05\x00") # no authentication

    let hdr = client.recvExact(4)
    if byteAt(hdr, 0) != 5 or byteAt(hdr, 1) != 1:
      client.sendSocksReply(0x07'u8) # command not supported
      return
    let atyp = byteAt(hdr, 3)
    var host = ""
    case atyp
    of 1:
      let raw = client.recvExact(4)
      host = $byteAt(raw, 0) & "." & $byteAt(raw, 1) & "." & $byteAt(raw, 2) & "." & $byteAt(raw, 3)
    of 3:
      let ln = byteAt(client.recvExact(1), 0)
      host = client.recvExact(ln)
    of 4:
      let raw = client.recvExact(16)
      var groups: seq[string]
      for i in 0 ..< 8:
        let g = (byteAt(raw, i * 2) shl 8) or byteAt(raw, i * 2 + 1)
        groups.add hexU16(g)
      host = groups.join(":")
    else:
      client.sendSocksReply(0x08'u8) # address type not supported
      return
    let p = client.recvExact(2)
    let port = (byteAt(p, 0) shl 8) or byteAt(p, 1)

    try:
      target = connectDirect(host, port)
    except CatchableError:
      client.sendSocksReply(0x05'u8) # connection refused/unreachable
      return
    client.sendSocksReply(0x00'u8)
    relayHttpLike(client, target)
  except CatchableError:
    discard
  finally:
    if target != nil: target.close()
    client.close()

proc listenerThread(spec: ListenerSpec) {.thread.} =
  let domain = if spec.host.contains(":"): AF_INET6 else: AF_INET
  var server = newSocket(domain = domain, buffered = false)
  try:
    server.setSockOpt(OptReuseAddr, true)
    server.bindAddr(spec.port, spec.host)
    server.listen()
    while true:
      var client: owned(Socket)
      server.accept(client)
      handleSocks5(client)
  except CatchableError:
    discard
  finally:
    server.close()

proc start*(s: var ProxyServer) =
  if not s.cfg.enabled: return
  if not s.cfg.socks5:
    raise newException(ValueError, "only SOCKS5 proxy mode is implemented in this backend")
  let specs = parseListen(s.cfg.listen)
  if specs.len == 0: raise newException(ValueError, "no proxy listen addresses")
  createThread(s.thread4, listenerThread, specs[0])
  s.hasThread4 = true
  if specs.len > 1:
    createThread(s.thread6, listenerThread, specs[1])
    s.hasThread6 = true
  s.running = true

proc stop*(s: var ProxyServer) =
  ## Listener threads are process-lifetime in this minimal backend. The daemon
  ## exits cleanly by terminating the process.
  s.running = false

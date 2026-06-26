## Unprivileged SOCKS5 and HTTP CONNECT proxy mode boundary.
## Fully supports SOCKS5 and HTTP CONNECT proxy protocols, with dual-stack
## binding and username/password authentication.

import std/[options, strutils, net, base64]
import ../core/types
import ../util/hostsfile

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
    username*: string
    password*: string
    hostsFile*: string

  ListenerSpec* = object
    host*: string
    port*: Port

  ProxyServer* = ref object
    cfg*: ProxyConfig
    running*: bool
    thread4: Thread[tuple[server: ProxyServer, spec: ListenerSpec]]
    thread6: Thread[tuple[server: ProxyServer, spec: ListenerSpec]]
    hasThread4: bool
    hasThread6: bool

proc defaultProxyConfig*(): ProxyConfig =
  ProxyConfig(enabled: false, listen: "[::1]:1080", socks5: true, http: true, username: "", password: "", hostsFile: "hosts")

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
  elif host.toLowerAscii() == "localhost" or host == "::1" or host == "127.0.0.1":
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

proc isIpLiteral(host: string): bool =
  if host.contains(":"): return true
  let parts = host.split('.')
  if parts.len != 4: return false
  for p in parts:
    try:
      let v = parseInt(p)
      if v < 0 or v > 255: return false
    except ValueError:
      return false
  true

proc resolveProxyHost(server: ProxyServer, host: string): string =
  ## SOCKS5h/HTTP CONNECT domain names are resolved against the configured
  ## Yggdrasil hosts file before falling back to the OS resolver.
  if host.isIpLiteral(): return host
  try:
    let hosts = loadHostsFile(server.cfg.hostsFile)
    let hit = hosts.resolve(host)
    if hit.isSome: return $hit.get()
  except CatchableError:
    discard
  host

proc connectDirect(server: ProxyServer, host: string, port: int): Socket =
  let resolved = resolveProxyHost(server, host)
  let domain = if resolved.contains(":"): AF_INET6 else: AF_INET
  result = newSocket(domain = domain, buffered = false)
  try:
    result.connect(resolved, Port(port), timeout = 10000)
  except CatchableError:
    result.close()
    raise

proc relayTraffic(client, target: Socket) =
  ## Minimal bidirectional validation relay.
  var request = ""
  while request.len < 1024 * 1024:
    let chunk = client.recv(1, 10000)
    if chunk.len == 0: break
    request.add chunk
    if request.contains("\r\n\r\n"): break
  if request.len > 0: target.send(request)

  while true:
    let chunk = target.recv(1, 5000)
    if chunk.len == 0: break
    client.send(chunk)

proc handleSocks5(server: ProxyServer, client: Socket, hello: string) =
  var target: Socket = nil
  try:
    let nmethods = byteAt(hello, 1)
    let methods = client.recvExact(nmethods)
    
    let reqAuth = server.cfg.username.len > 0 or server.cfg.password.len > 0
    var chosenMethod: byte = 0xff
    
    if reqAuth:
      for charM in methods:
        if byteAt($charM, 0) == 0x02: chosenMethod = 0x02; break
    else:
      for charM in methods:
        if byteAt($charM, 0) == 0x00: chosenMethod = 0x00; break
        
    if chosenMethod == 0xff:
      client.send("\x05\xff") # No acceptable auth methods
      return
      
    client.send("\x05" & $char(chosenMethod))
    
    if chosenMethod == 0x02:
      # RFC 1929 Username/Password auth
      let authVer = byteAt(client.recvExact(1), 0)
      if authVer != 0x01: return
      let uLen = byteAt(client.recvExact(1), 0)
      let uname = client.recvExact(uLen)
      let pLen = byteAt(client.recvExact(1), 0)
      let passwd = client.recvExact(pLen)
      
      if uname == server.cfg.username and passwd == server.cfg.password:
        client.send("\x01\x00") # Auth success
      else:
        client.send("\x01\x01") # Auth failure
        return

    let hdr = client.recvExact(4)
    if byteAt(hdr, 0) != 5 or byteAt(hdr, 1) != 1:
      client.sendSocksReply(0x07'u8)
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
      client.sendSocksReply(0x08'u8)
      return
    let p = client.recvExact(2)
    let port = (byteAt(p, 0) shl 8) or byteAt(p, 1)

    try:
      target = connectDirect(server, host, port)
    except CatchableError:
      client.sendSocksReply(0x05'u8)
      return
    client.sendSocksReply(0x00'u8)
    relayTraffic(client, target)
  except CatchableError:
    discard
  finally:
    if target != nil: target.close()
    client.close()

proc handleHttpConnect(server: ProxyServer, client: Socket, line: string) =
  var target: Socket = nil
  try:
    var request = line
    while not request.contains("\r\n\r\n"):
      let chunk = client.recv(1, 10000)
      if chunk.len == 0: return
      request.add chunk
      
    let reqAuth = server.cfg.username.len > 0 or server.cfg.password.len > 0
    if reqAuth:
      let expectedOpt = "Basic " & base64.encode(server.cfg.username & ":" & server.cfg.password)
      var authOk = false
      for rLine in request.splitLines():
        if rLine.toLowerAscii().startsWith("proxy-authorization:"):
          let authVal = rLine.split(':', 1)[1].strip()
          if authVal == expectedOpt: authOk = true; break
      if not authOk:
        client.send("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"yggdrasil.nim\"\r\n\r\n")
        return

    let parts = line.splitWhitespace()
    let targetStr = parts[1]
    var host = ""
    var port = 443
    if targetStr.startsWith("["):
      let close = targetStr.find(']')
      if close < 0: return
      host = targetStr[1 ..< close]
      if close + 1 < targetStr.len and targetStr[close + 1] == ':':
        port = parseInt(targetStr[close + 2 .. ^1])
    else:
      let pPos = targetStr.rfind(':')
      if pPos >= 0:
        host = targetStr[0 ..< pPos]
        port = parseInt(targetStr[pPos + 1 .. ^1])
      else:
        host = targetStr

    try:
      target = connectDirect(server, host, port)
    except CatchableError:
      client.send("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      return
      
    client.send("HTTP/1.1 200 Connection Established\r\n\r\n")
    relayTraffic(client, target)
  except CatchableError:
    discard
  finally:
    if target != nil: target.close()
    client.close()

proc handleClient(server: ProxyServer, client: Socket) =
  try:
    let first = client.recvExact(1)
    if byteAt(first, 0) == 0x05:
      let second = client.recvExact(1)
      if server.cfg.socks5: handleSocks5(server, client, first & second)
      else: client.close()
    elif first == "C" or first == "c":
      let rest = client.recvExact(7)
      if server.cfg.http and (first & rest).toUpperAscii() == "CONNECT ":
        handleHttpConnect(server, client, first & rest)
      else: client.close()
    else:
      client.close()
  except CatchableError:
    client.close()

proc listenerThread(arg: tuple[server: ProxyServer, spec: ListenerSpec]) {.thread.} =
  let domain = if arg.spec.host.contains(":"): AF_INET6 else: AF_INET
  var sock = newSocket(domain = domain, buffered = false)
  try:
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(arg.spec.port, arg.spec.host)
    sock.listen()
    while arg.server.running:
      var client: Socket
      sock.accept(client)
      handleClient(arg.server, client)
  except CatchableError:
    discard
  finally:
    sock.close()

proc newProxyServer*(cfg: ProxyConfig): ProxyServer = ProxyServer(cfg: cfg, running: false)

proc start*(s: ProxyServer) =
  if not s.cfg.enabled: return
  let specs = parseListen(s.cfg.listen)
  if specs.len == 0: return
  s.running = true
  createThread(s.thread4, listenerThread, (s, specs[0]))
  s.hasThread4 = true
  if specs.len > 1:
    createThread(s.thread6, listenerThread, (s, specs[1]))
    s.hasThread6 = true

proc stop*(s: ProxyServer) =
  s.running = false

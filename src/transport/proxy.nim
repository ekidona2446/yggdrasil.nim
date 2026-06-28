## Unprivileged SOCKS5 and HTTP CONNECT proxy mode boundary using Chronos.
## Fully supports SOCKS5 and HTTP CONNECT proxy protocols, with dual-stack
## binding and username/password authentication.

import std/[options, strutils, base64, os]
import chronos
import chronos/transports/stream
import ../core/types
import ../util/hostsfile
import ../util/ipnet

type
  ProxyConfig* = object
    enabled*: bool
    listen*: string
    socks5*: bool
    http*: bool
    username*: string
    password*: string
    hostsFile*: string

  ProxyServer* = ref object
    cfg*: ProxyConfig
    servers*: seq[StreamServer]
    running*: bool

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
  if host.isIpLiteral(): return host
  try:
    let hosts = loadHostsFile(server.cfg.hostsFile)
    let hit = hosts.resolve(host)
    if hit.isSome: return $hit.get()
  except CatchableError:
    discard
  host

proc relayTraffic(client, target: StreamTransport) {.async.} =
  try:
    proc pump(src, dst: StreamTransport, name: string) {.async.} =
      var buf: array[32768, byte]
      while not src.atEof():
        let n = await src.readOnce(addr buf[0], buf.len)
        if n <= 0:
          break
        let w = await dst.write(addr buf[0], n)
        if w != n:
          break
        
    let f1 = pump(client, target, "C->T")
    let f2 = pump(target, client, "T->C")
    let finished = await race(f1, f2)
    # Cancel the other one
    if not f1.finished: f1.cancelSoon()
    if not f2.finished: f2.cancelSoon()
    await allFutures(f1, f2)
  except CatchableError:
    discard
  finally:
    await allFutures(client.closeWait(), target.closeWait())

proc handleSocks5(server: ProxyServer, client: StreamTransport) {.async.} =
  try:
    var nmethodsBuf: array[1, byte]
    await client.readExactly(addr nmethodsBuf[0], 1)
    let nmethods = int(nmethodsBuf[0])
    var methods = newSeq[byte](nmethods)
    await client.readExactly(addr methods[0], nmethods)
    
    let reqAuth = server.cfg.username.len > 0 or server.cfg.password.len > 0
    var chosenMethod: byte = 0xff
    
    if reqAuth:
      for m in methods:
        if m == 0x02: chosenMethod = 0x02; break
    else:
      for m in methods:
        if m == 0x00: chosenMethod = 0x00; break
        
    if chosenMethod == 0xff:
      discard await client.write(@[0x05'u8, 0xff'u8])
      await client.closeWait()
      return
      
    discard await client.write(@[0x05'u8, chosenMethod])
    
    if chosenMethod == 0x02:
      var verBuf: array[1, byte]
      await client.readExactly(addr verBuf[0], 1)
      if verBuf[0] != 0x01: return
      var ulenBuf: array[1, byte]
      await client.readExactly(addr ulenBuf[0], 1)
      let ulen = int(ulenBuf[0])
      var uname = newString(ulen)
      await client.readExactly(addr uname[0], ulen)
      var plenBuf: array[1, byte]
      await client.readExactly(addr plenBuf[0], 1)
      let plen = int(plenBuf[0])
      var passwd = newString(plen)
      await client.readExactly(addr passwd[0], plen)
      
      if uname == server.cfg.username and passwd == server.cfg.password:
        discard await client.write(@[0x01'u8, 0x00'u8])
      else:
        discard await client.write(@[0x01'u8, 0x01'u8])
        await client.closeWait()
        return

    var hdr: array[4, byte]
    await client.readExactly(addr hdr[0], 4)
    if hdr[0] != 5 or hdr[1] != 1:
      discard await client.write(@[0x05'u8, 0x07'u8, 0x00'u8, 0x01'u8, 0, 0, 0, 0, 0, 0])
      await client.closeWait()
      return
      
    let atyp = hdr[3]
    var host = ""
    case atyp
    of 1:
      var raw: array[4, byte]
      await client.readExactly(addr raw[0], 4)
      host = $raw[0] & "." & $raw[1] & "." & $raw[2] & "." & $raw[3]
    of 3:
      var lnBuf: array[1, byte]
      await client.readExactly(addr lnBuf[0], 1)
      let ln = int(lnBuf[0])
      host = newString(ln)
      await client.readExactly(addr host[0], ln)
    of 4:
      var raw: array[16, byte]
      await client.readExactly(addr raw[0], 16)
      var groups: seq[string]
      for i in 0 ..< 8:
        groups.add strutils.toHex((uint16(raw[i*2]) shl 8) or uint16(raw[i*2+1]), 4)
      host = groups.join(":")
    else:
      discard await client.write(@[0x05'u8, 0x08'u8, 0x00'u8, 0x01'u8, 0, 0, 0, 0, 0, 0])
      await client.closeWait()
      return
      
    var pBuf: array[2, byte]
    await client.readExactly(addr pBuf[0], 2)
    let port = (int(pBuf[0]) shl 8) or int(pBuf[1])

    let resolved = server.resolveProxyHost(host)
    try:
      let address = initTAddress(resolved, port)
      let target = await connect(address)
      discard await client.write(@[0x05'u8, 0x00'u8, 0x00'u8, 0x01'u8, 0, 0, 0, 0, 0, 0])
      await relayTraffic(client, target)
    except CatchableError:
      discard await client.write(@[0x05'u8, 0x05'u8, 0x00'u8, 0x01'u8, 0, 0, 0, 0, 0, 0])
      await client.closeWait()
  except CatchableError:
    await client.closeWait()

proc handleHttpConnect(server: ProxyServer, client: StreamTransport, initial: string) {.async.} =
  try:
    var request = initial
    while not request.contains("\r\n\r\n"):
      var buf: array[1024, char]
      let n = await client.readOnce(addr buf[0], buf.len)
      if n <= 0: return
      for i in 0 ..< n: request.add buf[i]
      
    let reqAuth = server.cfg.username.len > 0 or server.cfg.password.len > 0
    if reqAuth:
      let expectedOpt = "Basic " & base64.encode(server.cfg.username & ":" & server.cfg.password)
      var authOk = false
      for rLine in request.splitLines():
        if rLine.toLowerAscii().startsWith("proxy-authorization:"):
          let authVal = rLine.split(':', 1)[1].strip()
          if authVal == expectedOpt: authOk = true; break
      if not authOk:
        discard await client.write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"yggdrasil.nim\"\r\n\r\n")
        await client.closeWait()
        return

    let parts = request.splitLines()[0].splitWhitespace()
    if parts.len < 2: return
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

    let resolved = server.resolveProxyHost(host)
    try:
      let address = initTAddress(resolved, port)
      let target = await connect(address)
      discard await client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      await relayTraffic(client, target)
    except CatchableError:
      discard await client.write("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      await client.closeWait()
  except CatchableError:
    await client.closeWait()

proc handleClient(server: ProxyServer, client: StreamTransport) {.async.} =
  try:
    var first: array[1, byte]
    await client.readExactly(addr first[0], 1)
    if first[0] == 0x05:
      if server.cfg.socks5: await handleSocks5(server, client)
      else: await client.closeWait()
    elif first[0] == byte('C') or first[0] == byte('c'):
      var rest = newString(7)
      await client.readExactly(addr rest[0], 7)
      if server.cfg.http and (char(first[0]) & rest).toUpperAscii() == "CONNECT ":
        await handleHttpConnect(server, client, char(first[0]) & rest)
      else: await client.closeWait()
    else:
      await client.closeWait()
  except CatchableError:
    await client.closeWait()

proc newProxyServer*(cfg: ProxyConfig): ProxyServer = ProxyServer(cfg: cfg, running: false)

proc start*(s: ProxyServer) =
  if not s.cfg.enabled: return
  
  let p = s.cfg.listen.rfind(':')
  if p < 0: return
  let host = s.cfg.listen[0 ..< p]
  let port = Port(parseInt(s.cfg.listen[p + 1 .. ^1]))
  
  let hosts = if host == "" or host == "*" or host == "0.0.0.0" or host == "::":
                @[initTAddress("0.0.0.0", port), initTAddress("::", port)]
              elif host == "localhost" or host == "127.0.0.1" or host == "::1":
                @[initTAddress("127.0.0.1", port), initTAddress("::1", port)]
              else:
                @[initTAddress(host, port)]

  for addr in hosts:
    try:
      let server = createStreamServer(addr, proc(server: StreamServer, transp: StreamTransport) {.async: (raises: []).} =
        try:
          await handleClient(s, transp)
        except CatchableError:
          discard
      )
      server.start()
      s.servers.add(server)
      stderr.writeLine "[proxy] Listening on ", $addr
    except CatchableError as e:
      stderr.writeLine "[proxy] Failed to listen on ", $addr, ": ", e.msg
  s.running = true

proc stop*(s: ProxyServer) =
  s.running = false
  for server in s.servers:
    server.stop()
    server.close()
  s.servers.setLen(0)

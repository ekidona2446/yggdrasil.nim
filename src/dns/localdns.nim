## Built-in local DNS resolver logic and a small UDP DNS forwarder.
##
## The resolver object is used by unit tests for hosts/DHT precedence. The UDP
## listener is intentionally minimal: it binds IPv4 and/or IPv6 loopback like the
## SOCKS proxy and forwards raw DNS packets to configured upstream resolvers.
## Yggdrasil-internal upstream DNS servers can be listed in config, but they only
## become reachable once the overlay data plane can route to `200::/7`/`300::/7`
## Yggdrasil addresses.

import std/[options, strutils]
from std/net import Socket, Port, AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP, newSocket, bindAddr, recvFrom, sendTo, setSockOpt, OptReuseAddr, close, getFd
when defined(posix):
  from posix import TFdSet, FD_ZERO, FD_SET, Timeval, Time, Suseconds, select
import ../util/[hostsfile, ipnet]
import ../core/[types, dht]

type
  DnsAnswerKind* = enum dnsNone, dnsHosts, dnsDht, dnsUpstream

  DnsAnswer* = object
    kind*: DnsAnswerKind
    address*: Option[IpAddress]
    ipv6*: Option[IPv6Address]
    ttlSeconds*: int

  LocalDnsConfig* = object
    enable*: bool
    listen*: string
    internalDomain*: string
    hostsPath*: string
    upstream*: seq[string]

  DnsListenerSpec* = object
    host*: string
    port*: Port
    upstream*: seq[string]

  LocalDnsServer* = object
    cfg*: LocalDnsConfig
    hosts*: HostsFile
    running*: bool
    thread4: Thread[DnsListenerSpec]
    thread6: Thread[DnsListenerSpec]
    hasThread4: bool
    hasThread6: bool

proc defaultLocalDnsConfig*(): LocalDnsConfig =
  LocalDnsConfig(enable: true, listen: "localhost:5053", internalDomain: ".yg",
                 hostsPath: "hosts.yg", upstream: @["1.1.1.1:53", "8.8.8.8:53"])

proc initLocalDnsServer*(cfg = defaultLocalDnsConfig()): LocalDnsServer =
  LocalDnsServer(cfg: cfg, hosts: loadHostsFile(cfg.hostsPath), running: false)

proc parseListen*(listen: string): seq[DnsListenerSpec] =
  let clean = listen.strip()
  if clean.len == 0: raise newException(ValueError, "empty DNS listen address")
  var host: string
  var portStr: string
  if clean.startsWith("["):
    let close = clean.find(']')
    if close < 0: raise newException(ValueError, "invalid bracketed IPv6 DNS listen address")
    host = clean[1 ..< close]
    if close + 1 >= clean.len or clean[close + 1] != ':':
      raise newException(ValueError, "missing DNS listen port")
    portStr = clean[close + 2 .. ^1]
  else:
    let p = clean.rfind(':')
    if p < 0: raise newException(ValueError, "missing DNS listen port")
    host = clean[0 ..< p]
    portStr = clean[p + 1 .. ^1]
  let portInt = parseInt(portStr)
  if portInt <= 0 or portInt > 65535: raise newException(ValueError, "DNS listen port out of range")
  let port = Port(portInt)
  if host.len == 0 or host == "*":
    result.add DnsListenerSpec(host: "0.0.0.0", port: port)
    result.add DnsListenerSpec(host: "::", port: port)
  elif host.toLowerAscii() == "localhost":
    result.add DnsListenerSpec(host: "127.0.0.1", port: port)
    result.add DnsListenerSpec(host: "::1", port: port)
  else:
    result.add DnsListenerSpec(host: host, port: port)

proc parseDnsEndpoint(endpoint: string): tuple[host: string, port: Port] =
  var clean = endpoint.strip()
  if clean.len == 0: raise newException(ValueError, "empty DNS upstream")
  if clean.startsWith("["):
    let close = clean.find(']')
    if close < 0: raise newException(ValueError, "invalid bracketed DNS upstream")
    result.host = clean[1 ..< close]
    if close + 1 < clean.len and clean[close + 1] == ':':
      result.port = Port(parseInt(clean[close + 2 .. ^1]))
    else:
      result.port = Port(53)
  else:
    let colonCount = clean.count(':')
    if colonCount == 1:
      let p = clean.rfind(':')
      result.host = clean[0 ..< p]
      result.port = Port(parseInt(clean[p + 1 .. ^1]))
    else:
      ## Bare IPv6 or bare hostname/IP without port.
      result.host = clean
      result.port = Port(53)

proc servfailResponse(query: string): string =
  if query.len < 12: return ""
  result = query
  result[2] = char(0x81) # QR + RD copied-ish
  result[3] = char(0x82) # RA + SERVFAIL
  result[6] = char(0); result[7] = char(0)   # ANCOUNT
  result[8] = char(0); result[9] = char(0)   # NSCOUNT
  result[10] = char(0); result[11] = char(0) # ARCOUNT

proc waitReadable(sock: Socket, timeoutMs: int): bool =
  when defined(posix):
    var fds: TFdSet
    FD_ZERO(fds)
    FD_SET(sock.getFd(), fds)
    var tv: Timeval
    tv.tv_sec = Time(timeoutMs div 1000)
    tv.tv_usec = Suseconds((timeoutMs mod 1000) * 1000)
    select(cint(sock.getFd()) + 1, addr fds, nil, nil, addr tv) > 0
  else:
    true

proc dnsRcode(reply: string): int =
  if reply.len < 4: return 2
  ord(reply[3]) and 0x0f

proc forwardDns(query: string, upstreams: seq[string], timeoutMs = 1500): string =
  var lastErrorReply = ""
  for upstream in upstreams:
    try:
      let ep = parseDnsEndpoint(upstream)
      let domain = if ep.host.contains(":"): AF_INET6 else: AF_INET
      var sock = newSocket(domain = domain, sockType = SOCK_DGRAM, protocol = IPPROTO_UDP, buffered = false)
      try:
        sock.sendTo(ep.host, ep.port, query)
        if not sock.waitReadable(timeoutMs): continue
        var reply = ""
        var replyHost = ""
        var replyPort: Port
        let n = sock.recvFrom(reply, 4096, replyHost, replyPort)
        if n >= 12:
          ## If an upstream says NXDOMAIN/SERVFAIL, continue to later upstreams.
          ## This allows public DNS first and Yggdrasil-internal DNS fallback for
          ## names that only exist inside the mesh.
          if reply.dnsRcode == 0:
            return reply
          if lastErrorReply.len == 0: lastErrorReply = reply
      finally:
        sock.close()
    except CatchableError:
      discard
  if lastErrorReply.len > 0: lastErrorReply else: servfailResponse(query)

proc dnsListenerThread(spec: DnsListenerSpec) {.thread.} =
  let domain = if spec.host.contains(":"): AF_INET6 else: AF_INET
  var sock = newSocket(domain = domain, sockType = SOCK_DGRAM, protocol = IPPROTO_UDP, buffered = false)
  try:
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(spec.port, spec.host)
    while true:
      var data = ""
      var clientHost = ""
      var clientPort: Port
      let n = sock.recvFrom(data, 4096, clientHost, clientPort)
      if n <= 0: continue
      let reply = forwardDns(data, spec.upstream)
      if reply.len > 0:
        sock.sendTo(clientHost, clientPort, reply)
  except CatchableError:
    discard
  finally:
    sock.close()

proc isInternal*(cfg: LocalDnsConfig, name: string): bool =
  let n = normalizeName(name)
  let d = normalizeName(cfg.internalDomain)
  n == d or n.endsWith("." & d) or (cfg.internalDomain.startsWith(".") and n.endsWith(cfg.internalDomain[1 .. ^1]))

proc nodeIdFromInternalName*(cfg: LocalDnsConfig, name: string): Option[NodeId] =
  if not cfg.isInternal(name): return none(NodeId)
  let n = normalizeName(name)
  let d = normalizeName(cfg.internalDomain)
  var left = n
  if left.endsWith("." & d): left = left[0 ..< left.len - d.len - 1]
  elif left.endsWith(d): left = left[0 ..< left.len - d.len]
  if left.len == 64:
    try: return some(nodeIdFromHex(left))
    except ValueError: return none(NodeId)
  none(NodeId)

proc resolveName*(server: LocalDnsServer, dhtState: Dht, name: string): DnsAnswer =
  ## Resolution precedence: custom hosts file, internal-domain DHT, upstream.
  let h = server.hosts.resolve(name)
  if h.isSome:
    return DnsAnswer(kind: dnsHosts, address: h, ttlSeconds: 300)

  let id = nodeIdFromInternalName(server.cfg, name)
  if id.isSome:
    let entry = dhtState.get(id.get())
    if entry.isSome:
      return DnsAnswer(kind: dnsDht, ipv6: some(deriveYggAddress(id.get())), ttlSeconds: 60)
    else:
      return DnsAnswer(kind: dnsNone, ttlSeconds: 0)

  DnsAnswer(kind: dnsUpstream, ttlSeconds: 0)

proc start*(s: var LocalDnsServer) =
  if not s.cfg.enable: return
  var specs = parseListen(s.cfg.listen)
  for i in 0 ..< specs.len:
    specs[i].upstream = s.cfg.upstream
  if specs.len == 0: raise newException(ValueError, "no DNS listen addresses")
  createThread(s.thread4, dnsListenerThread, specs[0])
  s.hasThread4 = true
  if specs.len > 1:
    createThread(s.thread6, dnsListenerThread, specs[1])
    s.hasThread6 = true
  s.running = true

proc stop*(s: var LocalDnsServer) =
  ## Listener threads are process-lifetime in this minimal backend.
  s.running = false

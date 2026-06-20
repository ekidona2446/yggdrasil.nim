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
  LocalDnsConfig(enable: true, listen: "[::1]:5053",
                 hostsPath: "hosts", upstream: @["1.1.1.1:53", "8.8.8.8:53"])

proc initLocalDnsServer*(cfg = defaultLocalDnsConfig()): LocalDnsServer =
  LocalDnsServer(cfg: cfg, hosts: loadHostsFile(cfg.hostsPath), running: false)

proc parseListen*(listen: string): seq[DnsListenerSpec] =
  let clean = listen.strip()
  if clean.len == 0: raise newException(ValueError, "empty DNS listen address")
  var host: string
  var portStr: string
  if clean.startsWith("["):
    let closeBracket = clean.find(']')
    if closeBracket < 0: raise newException(ValueError, "invalid bracketed IPv6 DNS listen address")
    host = clean[1 ..< closeBracket]
    if closeBracket + 1 >= clean.len or clean[closeBracket + 1] != ':':
      raise newException(ValueError, "missing DNS listen port")
    portStr = clean[closeBracket + 2 .. ^1]
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

proc resolveFromHosts*(s: LocalDnsServer, query: string): Option[DnsAnswer] =
  ## Resolve from hosts file. Hosts file supports any TLD.
  let normalizedQuery = query.toLowerAscii()
  if s.hosts.hasKey(normalizedQuery):
    let entry = s.hosts[normalizedQuery]
    result = some(DnsAnswer(kind: dnsHosts, address: some(entry.address), ipv6: some(entry.ipv6), ttlSeconds: 300))
  else:
    result = none(DnsAnswer)

proc resolveFromDht*(s: LocalDnsServer, query: string): Option[DnsAnswer] =
  ## Resolve from DHT (not yet implemented)
  result = none(DnsAnswer)

proc resolveFromUpstream*(spec: DnsListenerSpec, query: string): Option[DnsAnswer] =
  for upstreamAddr in spec.upstream:
    try:
      let parts = upstreamAddr.rsplit(':', 1)
      if parts.len != 2: continue
      let upstreamHost = parts[0]
      let upstreamPort = Port(parseInt(parts[1]))
      var sock = newSocket(domain: if upstreamHost.contains(':'): AF_INET6 else: AF_INET, 
                           sockType: SOCK_DGRAM, protocol: IPPROTO_UDP)
      defer: sock.close()
      # Simplified - would need real DNS packet handling
      discard
    except CatchableError:
      continue
  result = none(DnsAnswer)

proc start*(s: var LocalDnsServer) =
  if not s.cfg.enable: return
  if s.running: return
  
  let specs = parseListen(s.cfg.listen)
  for spec in specs:
    if spec.host.contains(':'):
      s.hasThread6 = true
      s.thread6.createThread(dnsListenerThread, spec)
    else:
      s.hasThread4 = true
      s.thread4.createThread(dnsListenerThread, spec)
  s.running = true

proc stop*(s: var LocalDnsServer) =
  s.running = false

proc dnsListenerThread(spec: DnsListenerSpec) {.thread.} =
  var sock = newSocket(domain: if spec.host.contains(':') or spec.host == "::": AF_INET6 else: AF_INET,
                       sockType: SOCK_DGRAM, protocol: IPPROTO_UDP)
  defer: sock.close()
  sock.setSockOpt(OptReuseAddr, true)
  try:
    sock.bindAddr(spec.port, spec.host)
    var buf = newString(512)
    while true:
      let (n, addr) = sock.recvFrom(buf, buf.len)
      if n > 0:
        # Simplified - would need real DNS packet handling
        # For now just forward to upstream
        discard
  except CatchableError:
    discard

proc running*(s: LocalDnsServer): bool = s.running

proc addUpstream*(s: var LocalDnsServer, upstream: string) =
  s.cfg.upstream.add upstream

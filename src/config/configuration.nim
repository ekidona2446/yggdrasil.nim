## Minimal TOML-like configuration loader for the documented example.
##
## It supports section headers, strings, integers, booleans, and one-line string
## arrays. Production may replace this with a full TOML parser without changing
## public config types.

import std/[strutils, os]

type
  NodeConfig* = object
    keyfile*: string
    name*: string

  PeersConfig* = object
    staticPeers*: seq[string]
    multicast*: bool
    multicastAddress*: string
    multicastPort*: int
    publicPeerLists*: seq[string]
    peerExchange*: bool

  CkrConfig* = object
    enabled*: bool

  TunConfigFile* = object
    enable*: bool
    name*: string
    mtu*: int
    ipv6*: string
    ipv4*: string

  ProxyConfigFile* = object
    enable*: bool
    listen*: string
    socks5*: bool
    http*: bool

  DnsConfig* = object
    enable*: bool
    listen*: string
    internalDomain*: string
    hostsFile*: string
    upstream*: seq[string]

  AdminConfig* = object
    listen*: seq[string]
    keepalive*: bool

  CryptoConfigFile* = object
    postQuantum*: bool
    kem*: string
    identityCertificate*: string
    aead*: string
    perHopProtection*: bool

  AppConfig* = object
    node*: NodeConfig
    peers*: PeersConfig
    ckr*: CkrConfig
    tun*: TunConfigFile
    proxy*: ProxyConfigFile
    dns*: DnsConfig
    admin*: AdminConfig
    crypto*: CryptoConfigFile

proc defaultConfig*(): AppConfig =
  result.node = NodeConfig(keyfile: "yggdrasil.key", name: "")
  result.peers = PeersConfig(staticPeers: @[], multicast: true,
                             multicastAddress: "ff02::114", multicastPort: 12345,
                             publicPeerLists: @[], peerExchange: true)
  result.ckr = CkrConfig(enabled: true)
  result.tun = TunConfigFile(enable: true, name: "yggl0", mtu: 65535, ipv6: "", ipv4: "")
  result.proxy = ProxyConfigFile(enable: false, listen: "127.0.0.1:1080", socks5: true, http: true)
  result.dns = DnsConfig(enable: true, listen: "localhost:5053", internalDomain: ".yg",
                         hostsFile: "hosts.yg", upstream: @["1.1.1.1:53", "8.8.8.8:53"])
  result.admin = AdminConfig(listen: @["unix://yggdrasil-admin.sock"], keepalive: true)
  result.crypto = CryptoConfigFile(postQuantum: true, kem: "ML-KEM-1024",
                                   identityCertificate: "Dilithium5+Ed25519",
                                   aead: "ChaCha20-Poly1305", perHopProtection: true)

proc stripQuotes(s: string): string =
  var x = s.strip()
  if x.len >= 2 and ((x[0] == '"' and x[^1] == '"') or (x[0] == '\'' and x[^1] == '\'')):
    x = x[1 ..< x.len - 1]
  x

proc parseBoolValue(s: string): bool =
  case s.strip().toLowerAscii()
  of "true", "yes", "1", "on": true
  of "false", "no", "0", "off": false
  else: raise newException(ValueError, "invalid boolean: " & s)

proc hasArrayCloseOutsideQuotes(s: string): bool =
  var inQuote = false
  var quote = '\0'
  for c in s:
    if inQuote:
      if c == quote: inQuote = false
    else:
      case c
      of '"', '\'':
        inQuote = true
        quote = c
      of ']':
        return true
      else:
        discard
  false

proc parseStringArray(s: string): seq[string] =
  let x = s.strip()
  if not (x.startsWith("[") and x.endsWith("]")):
    raise newException(ValueError, "expected array: " & s)
  var body = x[1 ..< x.len - 1].strip()
  if body.len == 0: return @[]
  var cur = ""
  var inQuote = false
  var quote = '\0'
  for c in body:
    if inQuote:
      if c == quote:
        inQuote = false
      else:
        cur.add c
    else:
      case c
      of '"', '\'':
        inQuote = true
        quote = c
      of ',':
        result.add cur.strip()
        cur = ""
      else:
        cur.add c
  if cur.strip().len > 0: result.add cur.strip()

proc setValue(cfg: var AppConfig, section, key, value: string) =
  case section
  of "Node":
    case key
    of "keyfile": cfg.node.keyfile = stripQuotes(value)
    of "name": cfg.node.name = stripQuotes(value)
    else: discard
  of "Peers":
    case key
    of "static": cfg.peers.staticPeers = parseStringArray(value)
    of "multicast": cfg.peers.multicast = parseBoolValue(value)
    of "multicastAddress": cfg.peers.multicastAddress = stripQuotes(value)
    of "multicastPort": cfg.peers.multicastPort = parseInt(value)
    of "publicPeerLists": cfg.peers.publicPeerLists = parseStringArray(value)
    of "peerExchange": cfg.peers.peerExchange = parseBoolValue(value)
    else: discard
  of "TUN":
    case key
    of "enable": cfg.tun.enable = parseBoolValue(value)
    of "name": cfg.tun.name = stripQuotes(value)
    of "mtu": cfg.tun.mtu = parseInt(value)
    of "ipv6": cfg.tun.ipv6 = stripQuotes(value)
    of "ipv4": cfg.tun.ipv4 = stripQuotes(value)
    else: discard
  of "Proxy":
    case key
    of "enable": cfg.proxy.enable = parseBoolValue(value)
    of "listen": cfg.proxy.listen = stripQuotes(value)
    of "socks5": cfg.proxy.socks5 = parseBoolValue(value)
    of "http": cfg.proxy.http = parseBoolValue(value)
    else: discard
  of "DNS":
    case key
    of "enable": cfg.dns.enable = parseBoolValue(value)
    of "listen": cfg.dns.listen = stripQuotes(value)
    of "internalDomain": cfg.dns.internalDomain = stripQuotes(value)
    of "hostsFile": cfg.dns.hostsFile = stripQuotes(value)
    of "upstream": cfg.dns.upstream = parseStringArray(value)
    else: discard
  of "Admin":
    case key
    of "listen": cfg.admin.listen = parseStringArray(value)
    of "keepalive": cfg.admin.keepalive = parseBoolValue(value)
    else: discard
  of "Crypto":
    case key
    of "postQuantum": cfg.crypto.postQuantum = parseBoolValue(value)
    of "kem": cfg.crypto.kem = stripQuotes(value)
    of "identityCertificate": cfg.crypto.identityCertificate = stripQuotes(value)
    of "aead": cfg.crypto.aead = stripQuotes(value)
    of "perHopProtection": cfg.crypto.perHopProtection = parseBoolValue(value)
    else: discard
  else:
    discard

proc loadConfig*(path: string): AppConfig =
  result = defaultConfig()
  if path.len == 0 or not fileExists(path): return
  var section = ""
  var multilineArrayKey = ""
  var multilineArrayBody = ""
  for raw0 in readFile(path).splitLines():
    var raw = raw0
    let hashAt = raw.find('#')
    if hashAt >= 0: raw = raw[0 ..< hashAt]
    let line = raw.strip()
    if line.len == 0: continue
    if multilineArrayKey.len > 0:
      multilineArrayBody.add line
      if hasArrayCloseOutsideQuotes(line):
        setValue(result, section, multilineArrayKey, multilineArrayBody)
        multilineArrayKey = ""
        multilineArrayBody = ""
      continue
    if line.startsWith("[") and line.endsWith("]"):
      section = line[1 ..< line.len - 1]
      continue
    let eq = line.find('=')
    if eq < 0: continue
    let key = line[0 ..< eq].strip()
    let value = line[eq + 1 .. ^1].strip()
    if value.startsWith("[") and not hasArrayCloseOutsideQuotes(value):
      multilineArrayKey = key
      multilineArrayBody = value
      continue
    setValue(result, section, key, value)

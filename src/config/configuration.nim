## Configuration module for yggdrasil.nim
##
## Supports TOML parsing/generation using nim-toml-serialization.
## Platform-specific defaults are loaded based on the OS.

import std/[strutils, os, tables, options]
import ../util/bytes

when defined(linux):
  import std/[distros]
elif defined(macosx):
  import std/[distros]
elif defined(windows):
  import std/[distros]

# =============================================================================
# Types
# =============================================================================

type
  NodeConfig* = object
    keyfile*: string
    name*: string
    nodeInfoPrivacy*: bool
    nodeInfo*: Table[string, string]

  PeersConfig* = object
    staticPeers*: seq[string]
    multicast*: bool
    multicastAddress*: string
    multicastPort*: int
    publicPeerLists*: seq[string]
    peerExchange*: bool

  TUNConfig* = object
    ## TUN parameters are determined in code based on OS.
    ## This is kept for backwards compatibility only.
    enable*: bool
    name*: string
    mtu*: int
    ipv6*: string
    ipv4*: string

  ProxyConfig* = object
    enable*: bool
    listen*: string
    socks5*: bool
    http*: bool

  DnsConfig* = object
    enable*: bool
    listen*: string
    hostsFile*: string
    upstream*: seq[string]

  AdminConfig* = object
    listen*: seq[string]
    keepalive*: bool

  CryptoConfig* = object
    postQuantum*: bool
    kem*: string
    identityCertificate*: string
    aead*: string
    perHopProtection*: bool
    tcpAo*: bool

  FirewallConfig* = object
    enable*: bool
    allowedPublicKeys*: seq[string]
    blockedPublicKeys*: seq[string]
    groupPassword*: string
    allowedOpenPorts*: seq[int]

  CKRRoute* = object
    id*: string
    remoteKey*: string
    destinationSubnets*: seq[string]
    allowedSourceSubnets*: seq[string]
    dynamic*: bool

  CKRConfig* = object
    enabled*: bool
    routes*: seq[CKRRoute]

  AppConfig* = object
    node*: NodeConfig
    peers*: PeersConfig
    tun*: TUNConfig
    proxy*: ProxyConfig
    dns*: DnsConfig
    admin*: AdminConfig
    crypto*: CryptoConfig
    firewall*: FirewallConfig
    ckr*: CKRConfig

# =============================================================================
# Platform-specific defaults
# =============================================================================

type PlatformDefaults* = object
  adminListen*: string
  configFile*: string
  tunMTU*: int
  tunName*: string
  multicastInterfaces*: seq[string]

when defined(linux):
  proc getPlatformDefaults*(): PlatformDefaults =
    PlatformDefaults(
      adminListen: "unix:///var/run/yggdrasil.sock",
      configFile: "/etc/yggdrasil.conf",
      tunMTU: 65535,
      tunName: "ygg0",
      multicastInterfaces: @[".*"]
    )
elif defined(macosx):
  proc getPlatformDefaults*(): PlatformDefaults =
    PlatformDefaults(
      adminListen: "unix:///var/run/yggdrasil.sock",
      configFile: "/etc/yggdrasil.conf",
      tunMTU: 65535,
      tunName: "utun",
      multicastInterfaces: @[".*"]
    )
elif defined(windows):
  proc getPlatformDefaults*(): PlatformDefaults =
    PlatformDefaults(
      adminListen: "tcp://127.0.0.1:9001",
      configFile: "C:\\\\ProgramData\\\\Yggdrasil\\\\yggdrasil.conf",
      tunMTU: 65535,
      tunName: "Yggdrasil",
      multicastInterfaces: @[".*"]
    )
else:
  proc getPlatformDefaults*(): PlatformDefaults =
    PlatformDefaults(
      adminListen: "tcp://127.0.0.1:9001",
      configFile: "yggdrasil.conf",
      tunMTU: 1280,
      tunName: "ygg0",
      multicastInterfaces: @[".*"]
    )

# =============================================================================
# Default configuration
# =============================================================================

proc defaultConfig*(): AppConfig =
  let platform = getPlatformDefaults()
  
  result.node = NodeConfig(
    keyfile: "yggdrasil.key",
    name: "",
    nodeInfoPrivacy: false,
    nodeInfo: initTable[string, string]()
  )
  
  result.peers = PeersConfig(
    staticPeers: @[],
    multicast: true,
    multicastAddress: "ff02::114",
    multicastPort: 12345,
    publicPeerLists: @[],
    peerExchange: true
  )
  
  result.tun = TUNConfig(
    enable: true,
    name: platform.tunName,
    mtu: platform.tunMTU,
    ipv6: "",
    ipv4: ""
  )
  
  result.proxy = ProxyConfig(
    enable: false,
    listen: "[::1]:1080",
    socks5: true,
    http: true
  )
  
  # DNS - no internalDomain, uses hostsFile for any TLD
  result.dns = DnsConfig(
    enable: true,
    listen: "[::1]:5053",
    hostsFile: "hosts",
    upstream: @["1.1.1.1:53", "8.8.8.8:53"]
  )
  
  result.admin = AdminConfig(
    listen: @[platform.adminListen],
    keepalive: true
  )
  
  # Crypto defaults
  when defined(linux):
    # TCP-AO only available on Linux with kernel >= 5.x
    let osSupportsTcpAo = true  # detectOs returns bool
    result.crypto = CryptoConfig(
      postQuantum: true,
      kem: "ML-KEM-1024",
      identityCertificate: "Dilithium5+Ed25519",
      aead: "ChaCha20-Poly1305",
      perHopProtection: true,
      tcpAo: osSupportsTcpAo
    )
  else:
    result.crypto = CryptoConfig(
      postQuantum: true,
      kem: "ML-KEM-1024",
      identityCertificate: "Dilithium5+Ed25519",
      aead: "ChaCha20-Poly1305",
      perHopProtection: true,
      tcpAo: false
    )
  
  result.firewall = FirewallConfig(
    enable: true,
    allowedPublicKeys: @[],
    blockedPublicKeys: @[],
    groupPassword: "",
    allowedOpenPorts: @[]
  )
  
  result.ckr = CKRConfig(
    enabled: true,
    routes: @[]
  )

# =============================================================================
# Simple TOML parser (temporary, until nim-toml-serialization is integrated)
# =============================================================================

proc stripQuotes(s: string): string =
  var x = s.strip()
  if x.len >= 2 and ((x[0] == '"' and x[^1] == '"') or (x[0] == '\'' and x[^1] == '\'')):
    x = x[1 ..< x.len - 1]
  x

proc parseBoolValue*(s: string): bool =
  case s.strip().toLowerAscii()
  of "true", "yes", "1", "on": true
  of "false", "no", "0", "off": false
  else: raise newException(ValueError, "invalid boolean: " & s)

proc parseStringArray*(s: string): seq[string] =
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

proc setValue(cfg: var AppConfig, section, key, value: string) =
  case section
  of "Node":
    case key
    of "keyfile": cfg.node.keyfile = stripQuotes(value)
    of "name": cfg.node.name = stripQuotes(value)
    of "nodeInfoPrivacy": cfg.node.nodeInfoPrivacy = parseBoolValue(value)
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
    of "hostsFile": cfg.dns.hostsFile = stripQuotes(value)
    of "upstream": cfg.dns.upstream = parseStringArray(value)
    # internalDomain removed - no longer needed
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
    of "tcpAo":
      when defined(linux):
        cfg.crypto.tcpAo = parseBoolValue(value)
      else:
        discard  # TCP-AO ignored on non-Linux platforms
    else: discard
  of "Firewall":
    case key
    of "enable": cfg.firewall.enable = parseBoolValue(value)
    of "allowedPublicKeys": cfg.firewall.allowedPublicKeys = parseStringArray(value)
    of "blockedPublicKeys": cfg.firewall.blockedPublicKeys = parseStringArray(value)
    of "groupPassword": cfg.firewall.groupPassword = stripQuotes(value)
    else: discard
  of "CKR":
    case key
    of "enabled": cfg.ckr.enabled = parseBoolValue(value)
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

# =============================================================================
# TOML generation
# =============================================================================

proc genQuoted(s: string): string =
  result = "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

proc generateConfigToml*(cfg: AppConfig, includeSecrets = false): string =
  result = "# Generated by yggdrasil.nim\n\n"
  
  # Node section
  result.add "[Node]\n"
  result.add "keyfile = " & genQuoted(cfg.node.keyfile) & "\n"
  if cfg.node.name.len > 0:
    result.add "name = " & genQuoted(cfg.node.name) & "\n"
  if cfg.node.nodeInfoPrivacy:
    result.add "nodeInfoPrivacy = true\n"
  if cfg.node.nodeInfo.len > 0:
    result.add "[Node.NodeInfo]\n"
    for k, v in cfg.node.nodeInfo:
      result.add genQuoted(k) & " = " & genQuoted(v) & "\n"
  result.add "\n"
  
  # Peers section
  result.add "[Peers]\n"
  result.add "static = ["
  for i, p in cfg.peers.staticPeers:
    if i > 0: result.add ", "
    result.add genQuoted(p)
  result.add "]\n"
  result.add "multicast = " & (if cfg.peers.multicast: "true" else: "false") & "\n"
  if cfg.peers.multicastAddress != "ff02::114":
    result.add "multicastAddress = " & genQuoted(cfg.peers.multicastAddress) & "\n"
  result.add "multicastPort = " & $cfg.peers.multicastPort & "\n"
  if cfg.peers.publicPeerLists.len > 0:
    result.add "publicPeerLists = ["
    for i, p in cfg.peers.publicPeerLists:
      if i > 0: result.add ", "
      result.add genQuoted(p)
    result.add "]\n"
  result.add "peerExchange = " & (if cfg.peers.peerExchange: "true" else: "false") & "\n"
  result.add "\n"
  
  # TUN section
  result.add "[TUN]\n"
  result.add "enable = " & (if cfg.tun.enable: "true" else: "false") & "\n"
  result.add "name = " & genQuoted(cfg.tun.name) & "\n"
  result.add "mtu = " & $cfg.tun.mtu & "\n"
  if cfg.tun.ipv6.len > 0:
    result.add "ipv6 = " & genQuoted(cfg.tun.ipv6) & "\n"
  if cfg.tun.ipv4.len > 0:
    result.add "ipv4 = " & genQuoted(cfg.tun.ipv4) & "\n"
  result.add "\n"
  
  # Proxy section
  result.add "[Proxy]\n"
  result.add "enable = " & (if cfg.proxy.enable: "true" else: "false") & "\n"
  result.add "listen = " & genQuoted(cfg.proxy.listen) & "\n"
  result.add "socks5 = " & (if cfg.proxy.socks5: "true" else: "false") & "\n"
  result.add "http = " & (if cfg.proxy.http: "true" else: "false") & "\n"
  result.add "\n"
  
  # DNS section - no internalDomain
  result.add "[DNS]\n"
  result.add "enable = " & (if cfg.dns.enable: "true" else: "false") & "\n"
  result.add "listen = " & genQuoted(cfg.dns.listen) & "\n"
  result.add "hostsFile = " & genQuoted(cfg.dns.hostsFile) & "\n"
  result.add "upstream = ["
  for i, u in cfg.dns.upstream:
    if i > 0: result.add ", "
    result.add genQuoted(u)
  result.add "]\n"
  result.add "\n"
  
  # Admin section
  result.add "[Admin]\n"
  result.add "listen = ["
  for i, l in cfg.admin.listen:
    if i > 0: result.add ", "
    result.add genQuoted(l)
  result.add "]\n"
  result.add "keepalive = " & (if cfg.admin.keepalive: "true" else: "false") & "\n"
  result.add "\n"
  
  # Crypto section
  result.add "[Crypto]\n"
  result.add "postQuantum = " & (if cfg.crypto.postQuantum: "true" else: "false") & "\n"
  result.add "kem = " & genQuoted(cfg.crypto.kem) & "\n"
  result.add "identityCertificate = " & genQuoted(cfg.crypto.identityCertificate) & "\n"
  result.add "aead = " & genQuoted(cfg.crypto.aead) & "\n"
  result.add "perHopProtection = " & (if cfg.crypto.perHopProtection: "true" else: "false") & "\n"
  when defined(linux):
    result.add "tcpAo = " & (if cfg.crypto.tcpAo: "true" else: "false") & "\n"
  # tcpAo is silently ignored on non-Linux platforms
  result.add "\n"
  
  # Firewall section
  if cfg.firewall.enable or cfg.firewall.groupPassword.len > 0:
    result.add "[Firewall]\n"
    result.add "enable = " & (if cfg.firewall.enable: "true" else: "false") & "\n"
    if cfg.firewall.allowedPublicKeys.len > 0:
      result.add "allowedPublicKeys = ["
      for i, k in cfg.firewall.allowedPublicKeys:
        if i > 0: result.add ", "
        result.add genQuoted(k)
      result.add "]\n"
    if cfg.firewall.blockedPublicKeys.len > 0:
      result.add "blockedPublicKeys = ["
      for i, k in cfg.firewall.blockedPublicKeys:
        if i > 0: result.add ", "
        result.add genQuoted(k)
      result.add "]\n"
    if cfg.firewall.groupPassword.len > 0:
      result.add "groupPassword = " & genQuoted(cfg.firewall.groupPassword) & "\n"
    result.add "\n"
  
  # CKR section
  if cfg.ckr.enabled or cfg.ckr.routes.len > 0:
    result.add "[CKR]\n"
    result.add "enabled = " & (if cfg.ckr.enabled: "true" else: "false") & "\n"
    for route in cfg.ckr.routes:
      result.add "[[CKR.routes]]\n"
      result.add "id = " & genQuoted(route.id) & "\n"
      result.add "remoteKey = " & genQuoted(route.remoteKey) & "\n"
      result.add "destinationSubnets = ["
      for i, s in route.destinationSubnets:
        if i > 0: result.add ", "
        result.add genQuoted(s)
      result.add "]\n"
      if route.allowedSourceSubnets.len > 0:
        result.add "allowedSourceSubnets = ["
        for i, s in route.allowedSourceSubnets:
          if i > 0: result.add ", "
          result.add genQuoted(s)
        result.add "]\n"
      result.add "dynamic = " & (if route.dynamic: "true" else: "false") & "\n"

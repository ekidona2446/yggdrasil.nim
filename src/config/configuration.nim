## Configuration module for yggdrasil.nim
##
## Uses nim-toml-serialization for parsing and generation.
## Platform-specific defaults are loaded at runtime.
##
## NOTE: TCP-AO was removed (not needed for Yggdrasil).
## TLS now planned to use WolfSSL instead of OpenSSL.

import std/[os, strutils, tables, options, net]
import toml_serialization/lexer
import toml_serialization/types
import toml_serialization
import serialization
import ../core/types
import ../core/publicpeers

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
    staticPeers*:       seq[string]
    multicast*:         bool
    multicastAddress*:  string
    multicastPort*:     int
    multicastInterface*: string
    ## URLs returning publicnodes.json-format data (empty → no JSON fetch).
    publicPeerLists*:   seq[string]
    ## GitHub repo slugs ("owner/repo") parsed via Trees API + raw Markdown.
    githubPeerRepos*:   seq[string]
    ## Human-readable refresh interval: "12h" | "1d" | "1w".
    peerCheckInterval*: string
    ## Drop peers whose Ironwood RTT exceeds this (0 = no limit).
    maxPingMs*:         int
    ## Path to persist the last known-good peer set.
    peerCacheFile*:     string
    peerExchange*:      bool

  TUNConfig* = object
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
    username*: string
    password*: string

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
    # tcpAo removed

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
# Helpers for TomlValueRef
# =============================================================================

proc getBool(val: TomlValueRef, default = false): bool =
  if val.isNil or val.kind != TomlKind.Bool: default else: val.boolVal

proc getInt(val: TomlValueRef, default = 0): int =
  if val.isNil or val.kind != TomlKind.Int: default else: val.intVal.int

proc getStr(val: TomlValueRef, default = ""): string =
  if val.isNil or val.kind != TomlKind.String: default else: val.stringVal

proc getSeqStr(val: TomlValueRef): seq[string] =
  if val.isNil or val.kind != TomlKind.Array: return
  for v in val.arrayVal:
    if v.kind == TomlKind.String:
      result.add v.stringVal

proc getSeqInt(val: TomlValueRef): seq[int] =
  if val.isNil or val.kind != TomlKind.Array: return
  for v in val.arrayVal:
    if v.kind == TomlKind.Int:
      result.add v.intVal.int

proc getTableStr(val: TomlValueRef): Table[string, string] =
  result = initTable[string, string]()
  if val.isNil or val.kind notin {TomlKind.Table, TomlKind.InlineTable}: return
  for k, v in pairs(val.tableVal):
    if v.kind == TomlKind.String:
      result[k] = v.stringVal

proc getToml(root: TomlValueRef, section, key: string): TomlValueRef =
  if root.isNil or root.kind notin {TomlKind.Table, TomlKind.InlineTable}: return nil
  let sec = root.tableVal.getOrDefault(section)
  if sec.isNil or sec.kind notin {TomlKind.Table, TomlKind.InlineTable}: return nil
  sec.tableVal.getOrDefault(key)

proc getSection(root: TomlValueRef, section: string): TomlValueRef =
  if root.isNil or root.kind notin {TomlKind.Table, TomlKind.InlineTable}: return nil
  let sec = root.tableVal.getOrDefault(section)
  if sec.isNil or sec.kind notin {TomlKind.Table, TomlKind.InlineTable}: return nil
  sec

proc parseTomlFile*(path: string): TomlValueRef =
  if not fileExists(path): return nil
  let content = readFile(path)
  var s = memoryInput(content)
  var lex = TomlLexer.init(s)
  result = parseToml(lex)

# =============================================================================
# Platform defaults
# =============================================================================

proc platformDefaults*(): tuple[adminListen: string, tunName: string, tunMtu: int] =
  when defined(linux):
    ("unix:///var/run/yggdrasil.sock", "ygg0", 65535)
  elif defined(macosx):
    ("unix:///var/run/yggdrasil.sock", "utun", 65535)
  elif defined(windows):
    ("tcp://127.0.0.1:9001", "Yggdrasil", 65535)
  else:
    ("tcp://127.0.0.1:9001", "ygg0", 1280)

# =============================================================================
# Default configuration
# =============================================================================

proc defaultConfig*(): AppConfig =
  let p = platformDefaults()

  result.node = NodeConfig(
    keyfile: "yggdrasil.key",
    name: "",
    nodeInfoPrivacy: false,
    nodeInfo: initTable[string, string]()
  )

  result.peers = PeersConfig(
    staticPeers:        @[],
    multicast:          true,
    multicastAddress:   "ff02::114",
    multicastPort:      12345,
    multicastInterface: ".*",
    publicPeerLists:    @[],
    githubPeerRepos:    @[],
    peerCheckInterval:  "1d",
    maxPingMs:          0,
    peerCacheFile:      "peers_cache.json",
    peerExchange:       true
  )

  result.tun = TUNConfig(
    enable: true,
    name: p.tunName,
    mtu: p.tunMtu,
    ipv6: "",
    ipv4: ""
  )

  result.proxy = ProxyConfig(
    enable: false,
    listen: "[::1]:1080",
    socks5: true,
    http: true,
    username: "",
    password: ""
  )

  result.dns = DnsConfig(
    enable: true,
    listen: "[::1]:5053",
    hostsFile: "hosts",
    upstream: @["1.1.1.1:53", "8.8.8.8:53"]
  )

  result.admin = AdminConfig(
    listen: @[p.adminListen],
    keepalive: true
  )

  result.crypto = CryptoConfig(
    postQuantum: false,
    kem: "ML-KEM-1024",
    identityCertificate: "Dilithium5+Ed25519",
    aead: "ChaCha20-Poly1305",
    perHopProtection: false
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
# Load config (nim-toml-serialization via TomlValueRef)
# =============================================================================

proc loadConfig*(path: string): AppConfig =
  result = defaultConfig()
  if path.len == 0 or not fileExists(path): return

  let root = parseTomlFile(path)
  if root.isNil: return

  # Node
  result.node.keyfile = getStr(getToml(root, "Node", "keyfile"), result.node.keyfile)
  result.node.name = getStr(getToml(root, "Node", "name"), result.node.name)
  result.node.nodeInfoPrivacy = getBool(getToml(root, "Node", "nodeInfoPrivacy"), result.node.nodeInfoPrivacy)
  let nodeInfoSec = getSection(root, "Node")
  if not nodeInfoSec.isNil:
    let nodeInfoSub = nodeInfoSec.tableVal.getOrDefault("NodeInfo")
    if not nodeInfoSub.isNil and nodeInfoSub.kind in {TomlKind.Table, TomlKind.InlineTable}:
      result.node.nodeInfo = getTableStr(nodeInfoSub)

  # Peers
  result.peers.staticPeers       = getSeqStr(getToml(root, "Peers", "static"))
  result.peers.multicast         = getBool(getToml(root, "Peers", "multicast"),          result.peers.multicast)
  result.peers.multicastAddress   = getStr(getToml(root, "Peers", "multicastAddress"),   result.peers.multicastAddress)
  result.peers.multicastPort      = getInt(getToml(root, "Peers", "multicastPort"),      result.peers.multicastPort)
  result.peers.multicastInterface = getStr(getToml(root, "Peers", "multicastInterface"), result.peers.multicastInterface)
  let jsonLists = getSeqStr(getToml(root, "Peers", "publicPeerLists"))
  if jsonLists.len > 0: result.peers.publicPeerLists = jsonLists
  let ghRepos = getSeqStr(getToml(root, "Peers", "githubPeerRepos"))
  if ghRepos.len > 0: result.peers.githubPeerRepos = ghRepos
  let checkIv = getStr(getToml(root, "Peers", "peerCheckInterval"), "")
  if checkIv.len > 0: result.peers.peerCheckInterval = checkIv
  result.peers.maxPingMs          = getInt(getToml(root, "Peers", "maxPingMs"),          result.peers.maxPingMs)
  let cacheFile = getStr(getToml(root, "Peers", "peerCacheFile"), "")
  if cacheFile.len > 0: result.peers.peerCacheFile = cacheFile
  result.peers.peerExchange      = getBool(getToml(root, "Peers", "peerExchange"),       result.peers.peerExchange)

  # TUN
  result.tun.enable = getBool(getToml(root, "TUN", "enable"), result.tun.enable)
  result.tun.name = getStr(getToml(root, "TUN", "name"), result.tun.name)
  result.tun.mtu = getInt(getToml(root, "TUN", "mtu"), result.tun.mtu)
  result.tun.ipv6 = getStr(getToml(root, "TUN", "ipv6"), result.tun.ipv6)
  result.tun.ipv4 = getStr(getToml(root, "TUN", "ipv4"), result.tun.ipv4)

  # Proxy
  result.proxy.enable = getBool(getToml(root, "Proxy", "enable"), result.proxy.enable)
  result.proxy.listen = getStr(getToml(root, "Proxy", "listen"), result.proxy.listen)
  result.proxy.socks5 = getBool(getToml(root, "Proxy", "socks5"), result.proxy.socks5)
  result.proxy.http = getBool(getToml(root, "Proxy", "http"), result.proxy.http)
  result.proxy.username = getStr(getToml(root, "Proxy", "username"), result.proxy.username)
  result.proxy.password = getStr(getToml(root, "Proxy", "password"), result.proxy.password)

  # DNS
  result.dns.enable = getBool(getToml(root, "DNS", "enable"), result.dns.enable)
  result.dns.listen = getStr(getToml(root, "DNS", "listen"), result.dns.listen)
  result.dns.hostsFile = getStr(getToml(root, "DNS", "hostsFile"), result.dns.hostsFile)
  result.dns.upstream = getSeqStr(getToml(root, "DNS", "upstream"))

  # Admin
  result.admin.listen = getSeqStr(getToml(root, "Admin", "listen"))
  if result.admin.listen.len == 0:
    result.admin.listen = @[platformDefaults().adminListen]
  result.admin.keepalive = getBool(getToml(root, "Admin", "keepalive"), result.admin.keepalive)

  # Crypto
  result.crypto.postQuantum = getBool(getToml(root, "Crypto", "postQuantum"), result.crypto.postQuantum)
  result.crypto.kem = getStr(getToml(root, "Crypto", "kem"), result.crypto.kem)
  result.crypto.identityCertificate = getStr(getToml(root, "Crypto", "identityCertificate"), result.crypto.identityCertificate)
  result.crypto.aead = getStr(getToml(root, "Crypto", "aead"), result.crypto.aead)
  result.crypto.perHopProtection = getBool(getToml(root, "Crypto", "perHopProtection"), result.crypto.perHopProtection)

  # Firewall
  result.firewall.enable = getBool(getToml(root, "Firewall", "enable"), result.firewall.enable)
  result.firewall.allowedPublicKeys = getSeqStr(getToml(root, "Firewall", "allowedPublicKeys"))
  result.firewall.blockedPublicKeys = getSeqStr(getToml(root, "Firewall", "blockedPublicKeys"))
  result.firewall.groupPassword = getStr(getToml(root, "Firewall", "groupPassword"), result.firewall.groupPassword)
  result.firewall.allowedOpenPorts = getSeqInt(getToml(root, "Firewall", "allowedOpenPorts"))

  # CKR
  result.ckr.enabled = getBool(getToml(root, "CKR", "enabled"), result.ckr.enabled)

# =============================================================================
# TOML generation (nim-toml-serialization)
# =============================================================================

proc genQuoted(s: string): string =
  result = "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

proc generateConfigToml*(cfg: AppConfig, includeSecrets = false): string =
  result = "# Generated by yggdrasil.nim\n\n"

  # Node
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

  # Peers
  result.add "[Peers]\n"
  result.add "static = ["
  for i, p in cfg.peers.staticPeers:
    if i > 0: result.add ", "
    result.add genQuoted(p)
  result.add "]\n"
  result.add "multicast = " & (if cfg.peers.multicast: "true" else: "false") & "\n"
  if cfg.peers.multicastAddress.len > 0 and cfg.peers.multicastAddress != "ff02::114":
    result.add "multicastAddress = " & genQuoted(cfg.peers.multicastAddress) & "\n"
  result.add "multicastPort = " & $cfg.peers.multicastPort & "\n"
  if cfg.peers.multicastInterface.len > 0:
    result.add "multicastInterface = " & genQuoted(cfg.peers.multicastInterface) & "\n"
  if cfg.peers.publicPeerLists.len > 0:
    result.add "publicPeerLists = ["
    for i, p in cfg.peers.publicPeerLists:
      if i > 0: result.add ", "
      result.add genQuoted(p)
    result.add "]\n"
  if cfg.peers.githubPeerRepos.len > 0:
    result.add "githubPeerRepos = ["
    for i, r in cfg.peers.githubPeerRepos:
      if i > 0: result.add ", "
      result.add genQuoted(r)
    result.add "]\n"
  if cfg.peers.peerCheckInterval.len > 0:
    result.add "peerCheckInterval = " & genQuoted(cfg.peers.peerCheckInterval) & "\n"
  if cfg.peers.maxPingMs > 0:
    result.add "maxPingMs = " & $cfg.peers.maxPingMs & "\n"
  if cfg.peers.peerCacheFile.len > 0:
    result.add "peerCacheFile = " & genQuoted(cfg.peers.peerCacheFile) & "\n"
  result.add "peerExchange = " & (if cfg.peers.peerExchange: "true" else: "false") & "\n"
  result.add "\n"

  # TUN
  result.add "[TUN]\n"
  result.add "enable = " & (if cfg.tun.enable: "true" else: "false") & "\n"
  result.add "name = " & genQuoted(cfg.tun.name) & "\n"
  result.add "mtu = " & $cfg.tun.mtu & "\n"
  if cfg.tun.ipv6.len > 0:
    result.add "ipv6 = " & genQuoted(cfg.tun.ipv6) & "\n"
  if cfg.tun.ipv4.len > 0:
    result.add "ipv4 = " & genQuoted(cfg.tun.ipv4) & "\n"
  result.add "\n"

  # Proxy
  result.add "[Proxy]\n"
  result.add "enable = " & (if cfg.proxy.enable: "true" else: "false") & "\n"
  result.add "listen = " & genQuoted(cfg.proxy.listen) & "\n"
  result.add "socks5 = " & (if cfg.proxy.socks5: "true" else: "false") & "\n"
  result.add "http = " & (if cfg.proxy.http: "true" else: "false") & "\n"
  if cfg.proxy.username.len > 0:
    result.add "username = " & genQuoted(cfg.proxy.username) & "\n"
  if cfg.proxy.password.len > 0:
    result.add "password = " & genQuoted(cfg.proxy.password) & "\n"
  result.add "\n"

  # DNS
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

  # Admin
  result.add "[Admin]\n"
  result.add "listen = ["
  for i, l in cfg.admin.listen:
    if i > 0: result.add ", "
    result.add genQuoted(l)
  result.add "]\n"
  result.add "keepalive = " & (if cfg.admin.keepalive: "true" else: "false") & "\n"
  result.add "\n"

  # Crypto
  result.add "[Crypto]\n"
  result.add "postQuantum = " & (if cfg.crypto.postQuantum: "true" else: "false") & "\n"
  result.add "kem = " & genQuoted(cfg.crypto.kem) & "\n"
  result.add "identityCertificate = " & genQuoted(cfg.crypto.identityCertificate) & "\n"
  result.add "aead = " & genQuoted(cfg.crypto.aead) & "\n"
  result.add "perHopProtection = " & (if cfg.crypto.perHopProtection: "true" else: "false") & "\n"
  result.add "\n"

  # Firewall
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
  if cfg.firewall.allowedOpenPorts.len > 0:
    result.add "allowedOpenPorts = ["
    for i, p in cfg.firewall.allowedOpenPorts:
      if i > 0: result.add ", "
      result.add $p
    result.add "]\n"
  result.add "\n"

  # CKR
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

# =============================================================================
# Public peer helpers and generated config (moved from yggdrasil.nim)
# =============================================================================

## fetchText, fetchAllPeers, fetchGithubMarkdownPeers etc. are defined in
## publicpeers.nim (already imported above).  Re-export for callers that only
## import configuration.
export publicpeers.fetchText, publicpeers.fetchAllPeers,
       publicpeers.fetchGithubMarkdownPeers,
       publicpeers.parsePeerCheckInterval, publicpeers.shouldRefreshCache,
       publicpeers.savePeerCache, publicpeers.loadPeerCache,
       publicpeers.filterByPing, publicpeers.peerCacheAge

proc tomlQuote(s: string): string =
  result = "\"" & s.replace("\\", "\\\\").replace("\"", "\\\"") & "\""

proc canTcpConnect*(peer: PeerUri; timeoutMs = 2500): bool =
  if peer.kind notin {tkTcp, tkTls, tkSocks, tkSocksTls, tkWebSocket, tkQuic}: return false
  let host = if peer.kind in {tkSocks, tkSocksTls}:
               peer.host.split('@')[^1].split(':')[0]
             else: peer.host
  let port = if peer.kind in {tkSocks, tkSocksTls}:
               parseInt(peer.host.split('@')[^1].split(':')[1])
             else: peer.port
  let domain = if host.contains(":"): AF_INET6 else: AF_INET
  var sock = newSocket(domain = domain, buffered = false)
  try:
    sock.connect(host, Port(port), timeout = timeoutMs)
    result = true
  except CatchableError:
    result = false
  finally:
    sock.close()

proc addDnsUpstreamsToConfig*(path: string; servers: seq[string]) =
  if servers.len == 0: return
  var content = if fileExists(path): readFile(path) else: ""
  var lines = content.splitLines()
  var changed = false
  var foundUpstream = false
  for i in 0 ..< lines.len:
    let stripped = lines[i].strip()
    if stripped.startsWith("upstream") and stripped.contains("[") and stripped.contains("]"):
      foundUpstream = true
      var insert = ""
      for srv in servers:
        if not lines[i].contains(srv):
          if insert.len > 0: insert.add ", "
          insert.add tomlQuote(srv)
      if insert.len > 0:
        let pos = lines[i].rfind(']')
        let needsComma = not lines[i][0 ..< pos].strip().endsWith("[")
        lines[i] = lines[i][0 ..< pos] & (if needsComma: ", " else: "") & insert & lines[i][pos .. ^1]
        changed = true
      break
  if not foundUpstream:
    if content.len > 0 and not content.endsWith("\n"): content.add "\n"
    content.add "\n[DNS]\n"
    content.add "enable = true\n"
    content.add "listen = \"[::1]:5053\"\n"
    content.add "upstream = ["
    for i, srv in servers:
      if i > 0: content.add ", "
      content.add tomlQuote(srv)
    content.add "]\n"
    writeFile(path, content)
  else:
    writeFile(path, lines.join("\n") & "\n")

proc writeGeneratedConfig*(path: string; peers: seq[PublicPeer]; listen: string; keyfile: string;
                           tunEnable, proxyEnable: bool;
                           jsonUrls: seq[string] = @[];
                           githubRepos: seq[string] = @[];
                           checkInterval = "1d"; maxPingMs = 0;
                           cacheFile = "peers_cache.json") =
  ## Write a complete, portable TOML config.  Do not hard-code Linux-only TUN
  ## names/admin sockets here: defaultConfig() already selects platform defaults
  ## for Linux, macOS, Windows and other targets at compile time.
  ##
  ## jsonUrls / githubRepos are written as-is from the caller — no URL is ever
  ## hard-coded in this function.
  var cfg = defaultConfig()
  cfg.node.keyfile = keyfile
  cfg.node.name = "generated-node"
  cfg.node.nodeInfo["implementation"] = "yggdrasil.nim"
  cfg.peers.staticPeers       = @[]
  for p in peers: cfg.peers.staticPeers.add(p.uri)
  cfg.peers.multicast         = false
  cfg.peers.peerExchange      = true
  cfg.peers.publicPeerLists   = jsonUrls
  cfg.peers.githubPeerRepos   = githubRepos
  cfg.peers.peerCheckInterval = checkInterval
  cfg.peers.maxPingMs         = maxPingMs
  cfg.peers.peerCacheFile     = cacheFile
  cfg.tun.enable = tunEnable
  # Keep cfg.tun.name/cfg.tun.mtu from platformDefaults().
  cfg.proxy.enable = proxyEnable
  cfg.proxy.listen = listen
  cfg.proxy.socks5 = true
  cfg.proxy.http   = true
  cfg.dns.enable   = true
  cfg.dns.hostsFile = "hosts"
  if cfg.dns.upstream.len == 0:
    cfg.dns.upstream = @["1.1.1.1:53", "8.8.8.8:53"]
  cfg.admin.keepalive       = true
  cfg.crypto.postQuantum    = false
  cfg.crypto.perHopProtection = false
  writeFile(path, generateConfigToml(cfg))

proc generateReachableConfig*(path: string;
                               jsonUrls: seq[string];
                               githubRepos: seq[string];
                               peerCount: int; listen: string;
                               keyfile: string; tunEnable, proxyEnable: bool;
                               checkInterval = "1d"; maxPingMs = 0;
                               cacheFile = "peers_cache.json";
                               token = ""): int =
  ## Fetch public peers from all configured sources, pick reachable ones via
  ## TCP probe, and write a TOML config file.  Returns the number of peers
  ## selected.  No source URL is hard-coded — if both jsonUrls and githubRepos
  ## are empty the function raises IOError.
  if jsonUrls.len == 0 and githubRepos.len == 0:
    raise newException(IOError,
      "no peer source configured (set publicPeerLists or githubPeerRepos)")

  let allPeers = fetchAllPeers(jsonUrls, githubRepos, onlyUp = true, token = token)
  var selected: seq[PublicPeer]
  for p in allPeers:
    if p.parsed.kind notin {tkTcp, tkTls, tkQuic, tkWebSocket}: continue
    if not canTcpConnect(p.parsed): continue
    selected.add p
    if selected.len >= peerCount: break
  if selected.len == 0:
    raise newException(IOError, "no reachable TCP/TLS/QUIC/WebSocket public peers found")
  writeGeneratedConfig(path, selected, listen, keyfile, tunEnable, proxyEnable,
                       jsonUrls, githubRepos, checkInterval, maxPingMs, cacheFile)
  result = selected.len

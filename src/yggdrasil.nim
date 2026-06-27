## Main entry point for yggdrasil.nim.
##
## Async Chronos-based Yggdrasil mesh overlay daemon.
## Supports TCP, TLS, SOCKS5, QUIC peer connections via the LinkManager.
## Coordinates:
## - LinkManager (TCP/TLS/SOCKS/QUIC peer connections)
## - PacketConn (overlay read/write + Ironwood router)
## - TUN adapter (kernel network interface)
## - Proxy server (SOCKS5/HTTP)
## - Admin socket (JSON-RPC)
## - DNS resolver

import std/[os, parseopt, strutils, options, sequtils]
import chronos
import toml_serialization
import toml_serialization/lexer
import toml_serialization/types

import ./config/configuration
import ./core/[identity, types, peermanager, tree, dht, ckr, publicpeers]
import ./ironwood/[wire, router, routerstate, packetconn, routertypes]
import ./transport/[asynclink, asyncpeer]
import ./admin/api
import ./dns/localdns
import ./transport/proxy
import ./transport/peerquic
import ./tun/tunadapter

const Version* = "0.0.1"

# ── Data plane: TUN <-> PacketConn ───────────────────────────────────────

proc tunToOverlay(tun: TunAdapter, pc: PacketConn) {.async.} =
  ## Read packets from TUN, write to overlay via PacketConn.
  ## Mirrors Go's ipv6rwc: drop non-IPv6, non-Yggdrasil (200::/7, 300::/7),
  ## and prefix with typeSessionTraffic (0x00) before handing to PacketConn.
  while tun.running:
    try:
      let packet = await tun.readPacket()
      if packet.len == 0: continue

      let version = packet[0] shr 4
      var destKey: NodeId

      if version == 6 and packet.len >= 40:
        var destAddr: IPv6Address
        for i in 0 ..< 16: destAddr[i] = packet[24 + i]
        if destAddr[0] notin {0x02'u8, 0x03'u8}:
          # Not a Yggdrasil unicast address (200::/7 or 300::/7); drop.
          continue
        destKey = keyPrefixForYggAddress(destAddr)
        stderr.writeLine "[dataplane] TUN -> overlay dest=" & toIPv6String(destAddr) & " pktLen=" & $packet.len & " destAddr0=0x" & toHex(destAddr[0]) & " destKey=" & toHex(destKey)
      elif version == 4 and packet.len >= 20:
        continue
      else:
        continue

      # Prepend typeSessionTraffic byte (0x00) matching Go's Core.WriteTo.
      # Go's Core.ReadFrom inspects the first byte to distinguish traffic
      # (0x00) from protocol messages (0x01); IPv6 packets start with 0x60
      # and would be silently dropped without the type prefix.
      var typed: seq[byte]
      typed.add 0x00'u8
      for b in packet: typed.add b
      try:
        await pc.writeTo(destKey, typed)
      except CatchableError as e:
        stderr.writeLine "[dataplane] writeTo error: " & e.msg
    except CancelledError:
      break
    except CatchableError as e:
      if not tun.running: break
      await sleepAsync(chronos.milliseconds(1))

proc overlayToTun(pc: PacketConn, tun: TunAdapter) {.async.} =
  ## Read deliveries from PacketConn, write to TUN.
  ## Strips the typeSessionTraffic/typeSessionProto prefix byte that Go's
  ## Core.ReadFrom adds; only typeSessionTraffic (0x00) data is forwarded
  ## to the TUN as an IPv6 packet.
  var buf = newSeq[byte](65536)
  while tun.running:
    try:
      let (n, source) = await pc.readFrom(addr buf[0], buf.len)
      if n == 0: continue
      if buf[0] != 0x00: continue  # skip non-traffic (typeSessionProto etc.)
      let pktLen = n - 1
      if pktLen == 0: continue
      stderr.writeLine "[dataplane] overlay -> TUN src=" & short(source) & " n=" & $pktLen
      await tun.writePacket(buf[1 ..< n])
    except CancelledError:
      break
    except CatchableError as e:
      if not tun.running: break
      await sleepAsync(chronos.milliseconds(1))

# ── Async daemon ──────────────────────────────────────────────────────────

proc runDaemon(listenAddrs, peerUris: seq[string], keyfile: string,
               tunEnable, proxyEnable, dnsEnable: bool,
               proxyListen, dnsListen, dnsHostsFile: string,
               dnsUpstream: seq[string],
               tunName: string, tunMtu: int) {.async.} =
  var crypto: RouterCrypto
  {.cast(gcsafe).}:
    try:
      crypto = loadOrCreateRouterCrypto(keyfile)
    except Exception:
      echo "failed to load key: ", getCurrentExceptionMsg()
      return

  let address = deriveYggAddress(crypto.publicKey)
  let subnet = deriveYggSubnet(crypto.publicKey)
  let ipv6Str = toIPv6String(address)
  echo "yggdrasil.nim ", Version, " starting..."
  echo "publicKey=", toHex(crypto.publicKey)
  echo "address=", ipv6Str
  echo "subnet=", toSubnetString(subnet)

  var packetConn: PacketConn
  {.cast(gcsafe).}:
    try:
      packetConn = newPacketConn(crypto)
    except Exception:
      echo "failed to create PacketConn: ", getCurrentExceptionMsg()
      return
  await packetConn.start()

  let linkConfig = LinkConfig(
    listenAddrs: listenAddrs,
    peerUris: peerUris,
    password: @[],
  )
  let linkMgr = newLinkManager(crypto, packetConn, linkConfig)
  await linkMgr.start()

  # QUIC manager (optional, for quic:// peers)
  var quicMgr: QuicManager = nil
  var hasQuicPeers = false
  for uri in peerUris:
    try:
      let p = parsePeerUri(uri)
      if p.kind == tkQuic:
        hasQuicPeers = true
        break
    except CatchableError:
      discard
  if hasQuicPeers or listenAddrs.anyIt(it.startsWith("quic://")):
    quicMgr = newQuicManager(crypto)
    quicMgr.setupQuicManager()
    echo "QUIC manager initialized"

  # ── TUN adapter ─────────────────────────────────────────────────────────
  var tun: TunAdapter = nil
  if tunEnable:
    try:
      let platformTun = defaultTunConfig()
      let tunCfg = tunadapter.TunConfig(
        enable: true,
        name: if tunName.len > 0: tunName else: platformTun.name,
        mtu: if tunMtu > 0: tunMtu else: platformTun.mtu,
        ipv6: ipv6Str,
        ipv4: "",
        tunFd: cint(-1),
      )
      echo "TUN driver: default (MTU: ", tunCfg.mtu, ")"
      tun = openTun(tunCfg)
      tun.configureInterface(ipv6Str, tunCfg.mtu)
      tun.configureRoutes()
      tun.startIo()
      echo "TUN interface ", tun.ifName, " configured with ", ipv6Str, "/7"

      asyncSpawn tunToOverlay(tun, packetConn)
      asyncSpawn overlayToTun(packetConn, tun)
      echo "Data plane active: TUN <-> PacketConn"
    except CatchableError as e:
      echo "TUN setup failed: ", e.msg
      echo "Continuing without TUN (proxy-only mode)"

  # ── Proxy ───────────────────────────────────────────────────────────────
  if proxyEnable:
    var ps = ProxyServer(
      cfg: proxy.ProxyConfig(enabled: true, listen: proxyListen, socks5: true, http: true, username: "", password: "", hostsFile: dnsHostsFile),
      running: false,
    )
    ps.start()
    echo "Proxy listening at ", proxyListen

  # ── DNS ───────────────────────────────────────────────────────────────
  if dnsEnable:
    let dnsCfg = LocalDnsConfig(
      enable: dnsEnable,
      listen: dnsListen,
      hostsPath: dnsHostsFile,
      upstream: dnsUpstream,
    )
    var dns = initLocalDnsServer(dnsCfg)
    dns.start()
    echo "DNS resolver listening at ", dnsListen

  echo "Daemon running. Press Ctrl+C to exit."
  echo "Peers: ", peerUris.len, " configured | TUN: ", if tun != nil: tun.ifName else: "disabled"
  if quicMgr != nil:
    echo "QUIC: enabled"

  while true:
    await sleepAsync(chronos.milliseconds(1000))

# ── CLI ───────────────────────────────────────────────────────────────────

proc usage() =
  echo """
yggdrasil.nim - Yggdrasil mesh overlay daemon (Chronos async)

Usage:
  yggdrasil [options]

Options:
  --config=PATH           TOML config file
  --keyfile=PATH          Override Node.keyfile
  --listen=ADDR           Listen address (repeatable, e.g. "tcp://0.0.0.0:12345")
  --peer=URI              Peer URI to connect to (repeatable)
                          Supported: tcp://, tls://, ws://, wss://, quic://,
                                     socks://, sockstls://
                          URI params: ?key=, ?sni=, ?priority=, ?password=, ?maxbackoff=
  --no-tun                Disable TUN mode
  --proxy                 Enable SOCKS5/HTTP proxy
  --socks5-addr=ADDR      Enable proxy and set SOCKS5/HTTP listen address
  --self                  Print node identity and exit
  --version               Print version and exit
  --run                   Start the daemon

  --check-public-peers=URL_OR_FILE
                          Fetch/read and parse official public peer JSON, then exit
  --generate-config=PATH  Generate TOML config with reachable up public peers
  --generate-key=PATH     Generate/reuse Ed25519 Yggdrasil key file and print address
  --generate-proxy-config=PATH
                          Backward-compatible alias for --generate-config + --proxy-mode
  --proxy-mode            Proxy only, no TUN
  --tun-mode              TUN only, no proxy
  --tun-proxy-mode        Both TUN and proxy
  --peer-count=N          Number of reachable up peers in generated config (default: 8)
  --add-dns=ADDR          Add DNS upstream to --config file and exit (repeatable)
  --admin-json=JSON       Dispatch one JSON-RPC admin request and exit
  -h, --help              Show help

Peer URI examples:
  tcp://1.2.3.4:12345
  tls://example.com:443
  tls://1.2.3.4:443?sni=example.com
  ws://example.com:80/path
  wss://example.com:443/path
  quic://example.com:443
  socks://proxy.local:1080/1.2.3.4:12345
  sockstls://user:pass@proxy.local:1080/example.com:443?sni=example.com
  tcp://1.2.3.4:12345?key=abcdef1234...&priority=1&password=secret
"""

proc main() =
  var configPath = ""
  var forceProxy = false
  var noTun = false
  var modeProxyOnly = false
  var modeTunOnly = false
  var modeTunProxy = false
  var printSelf = false
  var printVersion = false
  var adminJson = ""
  var runFlag = false
  var keyOverride = ""
  var socks5Addr = ""
  var publicPeersSource = ""
  var generateConfigPath = ""
  var generateKeyPath = ""
  var peerCount = 8
  var listenAddrs: seq[string]
  var peerUris: seq[string]
  var dnsToAdd: seq[string]
  var tunNameOverride = ""

  var p = initOptParser(commandLineParams())
  for kind, key, val in p.getopt():
    case kind
    of cmdLongOption, cmdShortOption:
      case key
      of "config": configPath = val
      of "tun-name": tunNameOverride = val
      of "keyfile": keyOverride = val
      of "listen": listenAddrs.add val
      of "peer": peerUris.add val
      of "proxy": forceProxy = true
      of "proxy-mode":
        modeProxyOnly = true
        forceProxy = true
        noTun = true
      of "tun-mode":
        modeTunOnly = true
      of "tun-proxy-mode", "tun-with-proxy":
        modeTunProxy = true
        forceProxy = true
      of "socks5-addr":
        forceProxy = true
        socks5Addr = val
      of "no-tun": noTun = true
      of "self": printSelf = true
      of "version": printVersion = true
      of "check-public-peers": publicPeersSource = val
      of "generate-config": generateConfigPath = val
      of "generate-key": generateKeyPath = val
      of "generate-proxy-config":
        generateConfigPath = val
        modeProxyOnly = true
        forceProxy = true
        noTun = true
      of "peer-count": peerCount = parseInt(val)
      of "add-dns": dnsToAdd.add val
      of "admin-json": adminJson = val
      of "run": runFlag = true
      of "h", "help": usage(); return
      else:
        echo "unknown option: ", key
    of cmdArgument:
      discard
    of cmdEnd:
      discard

  if printVersion:
    echo "yggdrasil.nim ", Version
    return

  if generateKeyPath.len > 0:
    try:
      let c = loadOrCreateRouterCrypto(generateKeyPath)
      echo "keyfile=", generateKeyPath
      echo "publicKey=", toHex(c.publicKey)
      echo "address=", toIPv6String(deriveYggAddress(c.publicKey))
    except CatchableError as e:
      quit "generate key failed: " & e.msg, 1
    return

  if dnsToAdd.len > 0:
    configuration.addDnsUpstreamsToConfig(configPath, dnsToAdd)
    echo "added ", dnsToAdd.len, " DNS upstream(s) to ", configPath
    return

  if publicPeersSource.len > 0:
    let content = configuration.fetchText(publicPeersSource)
    let summary = summarizePublicPeersJson(content)
    let peers = parsePublicPeersJson(content, onlyUp = true)
    echo "publicPeers ", summary
    for i in 0 ..< min(10, peers.len):
      let p = peers[i]
      echo p.uri, " region=", p.region, " up=", p.up, " responseMs=", p.responseMs
    return

  if generateConfigPath.len > 0:
    if peerCount <= 0: quit "--peer-count must be positive", 2
    let source = if publicPeersSource.len > 0: publicPeersSource else: configuration.DefaultPublicPeersUrl
    let listen = if socks5Addr.len > 0: socks5Addr else: "[::1]:1080"
    let keyfile = if keyOverride.len > 0: keyOverride else: "yggdrasil.key"
    try:
      discard loadOrCreateRouterCrypto(keyfile)
    except CatchableError as e:
      quit "could not create keyfile " & keyfile & ": " & e.msg, 1
    # Default generated config is TUN-first.  Use --generate-proxy-config or
    # --proxy-mode for the old proxy-only behaviour, and --tun-proxy-mode for both.
    var tunEnable = true
    var proxyEnable = false
    if modeTunOnly:
      tunEnable = true
      proxyEnable = false
    elif modeTunProxy:
      tunEnable = true
      proxyEnable = true
    elif modeProxyOnly:
      tunEnable = false
      proxyEnable = true
    let n = configuration.generateReachableConfig(generateConfigPath, source, peerCount, listen, keyfile, tunEnable, proxyEnable)
    echo "generated ", generateConfigPath, " with ", n, " reachable public peers; tun=", tunEnable, " proxy=", proxyEnable, " proxy listen=", listen
    return

  # Load config
  var cfg = loadConfig(configPath)
  if keyOverride.len > 0: cfg.node.keyfile = keyOverride
  if modeProxyOnly:
    cfg.proxy.enable = true
    cfg.tun.enable = false
  elif modeTunOnly:
    cfg.proxy.enable = false
    cfg.tun.enable = true
  elif modeTunProxy:
    cfg.proxy.enable = true
    cfg.tun.enable = true
  if forceProxy: cfg.proxy.enable = true
  if socks5Addr.len > 0: cfg.proxy.listen = socks5Addr
  if noTun: cfg.tun.enable = false

  # Merge CLI peer URIs with config
  if peerUris.len == 0: peerUris = cfg.peers.staticPeers
  if listenAddrs.len == 0:
    if cfg.admin.listen.len > 0:
      for a in cfg.admin.listen:
        try:
          let parsed = parsePeerUri(a)
          if parsed.kind == tkTcp:
            listenAddrs.add a
        except CatchableError:
          discard
    if listenAddrs.len == 0:
      listenAddrs.add("tcp://0.0.0.0:12345")

  # Print identity and exit
  if printSelf:
    try:
      let crypto = loadOrCreateRouterCrypto(cfg.node.keyfile)
      echo "publicKey=", toHex(crypto.publicKey)
      echo "address=", toIPv6String(deriveYggAddress(crypto.publicKey))
    except CatchableError as e:
      echo "error: ", e.msg
    return

  # Admin JSON-RPC
  if adminJson.len > 0:
    let id = loadOrCreateIdentity(cfg.node.keyfile)
    var tr = initTree(id.publicKey)
    var dd = initDht(id.publicKey)
    dd.refreshSelf(tr.selfCoords, tr.revision)
    var routes = initCkrTable()
    var pm = initPeerManager(defaultPeerManagerConfig())
    var admin = initAdminContext(id, tr, dd, routes, pm, cfg.admin.keepalive)
    echo admin.dispatchRpc(adminJson)
    return

  if not runFlag:
    echo "Use --run to start the daemon."
    return

  # Run async daemon
  let proxyListen = if socks5Addr.len > 0: socks5Addr else: cfg.proxy.listen
  let platformTun = defaultTunConfig()
  let tunName = if tunNameOverride.len > 0: tunNameOverride else: platformTun.name
  waitFor runDaemon(
    listenAddrs, peerUris, cfg.node.keyfile,
    cfg.tun.enable, cfg.proxy.enable, cfg.dns.enable,
    proxyListen, cfg.dns.listen, cfg.dns.hostsFile, cfg.dns.upstream,
    tunName, cfg.tun.mtu,
  )

when isMainModule:
  main()

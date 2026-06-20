## Async Chronos-based link layer for Yggdrasil.
##
## Handles:
## - TCP outgoing connections (tcp://)
## - TLS outgoing connections (tls://) via OpenSSL thread bridge
## - TCP/TLS incoming connections (listen/accept)
## - SOCKS5 proxy connections (socks://, sockstls://)
## - Metadata handshake (the `meta` preamble before Ironwood frames)
## - Multiple simultaneous peer connections with reconnection
## - URI query parameters: ?key=, ?sni=, ?priority=, ?password=, ?maxbackoff=

import std/[strutils, tables, options, sequtils, os]
import chronos
import chronos/transports/stream
import ../core/types
import ../core/peermanager
import ../crypto/sodium
import ./router
import ./routerstate
import ./packetconn
import ./asyncpeer
import ./routertypes

when defined(ssl):
  import ../transport/peertls

import ../transport/peerws

const
  ProtocolVersionMajor = 0'u16
  ProtocolVersionMinor = 5'u16
  MetaVersionMajor = 0'u16
  MetaVersionMinor = 1'u16
  MetaPublicKey = 2'u16
  MetaPriority = 3'u16
  HandshakeTimeoutMs = 7000
  DefaultMaxBackoffMs = 60000
  SocksConnectTimeoutMs = 10000

# ── Metadata encoding/decoding ──────────────────────────────────────────────

proc putU16be(buf: var seq[byte], x: uint16) =
  buf.add byte((x shr 8) and 0xff)
  buf.add byte(x and 0xff)

proc readU16be(data: openArray[byte], off: int): uint16 =
  if off + 2 > data.len: raise newException(ValueError, "short uint16")
  (uint16(data[off]) shl 8) or uint16(data[off + 1])

proc encodeMetadata*(crypto: RouterCrypto, priority: byte = 0,
                     password: seq[byte] = @[]): seq[byte] {.gcsafe.} =
  var body: seq[byte]
  body.putU16be(MetaVersionMajor)
  body.putU16be(2)
  body.putU16be(ProtocolVersionMajor)
  body.putU16be(MetaVersionMinor)
  body.putU16be(2)
  body.putU16be(ProtocolVersionMinor)
  body.putU16be(MetaPublicKey)
  body.putU16be(32)
  for b in crypto.publicKey.bytes: body.add b
  body.putU16be(MetaPriority)
  body.putU16be(1)
  body.add priority
  let hash = blake2b512(crypto.publicKey.bytes, password)
  let sig = signDetached(crypto.secretKey, hash)
  for b in sig: body.add b
  result = @[byte(ord('m')), byte(ord('e')), byte(ord('t')), byte(ord('a'))]
  result.putU16be(uint16(body.len))
  for b in body: result.add b

proc decodeMetadata*(wire: openArray[byte]): tuple[publicKey: NodeId, major, minor: uint16, priority: byte] =
  if wire.len < 70: raise newException(ValueError, "metadata too short")
  if wire[0] != byte(ord('m')) or wire[1] != byte(ord('e')) or
     wire[2] != byte(ord('t')) or wire[3] != byte(ord('a')):
    raise newException(ValueError, "invalid metadata preamble")
  let hlen = int(readU16be(wire, 4))
  if hlen != wire.len - 6:
    raise newException(ValueError, "metadata length mismatch")
  let endNoSig = wire.len - 64
  var off = 6
  while off + 4 <= endNoSig:
    let op = readU16be(wire, off)
    let oplen = int(readU16be(wire, off + 2))
    off += 4
    if off + oplen > endNoSig: break
    case op
    of MetaVersionMajor:
      if oplen == 2: result.major = readU16be(wire, off)
    of MetaVersionMinor:
      if oplen == 2: result.minor = readU16be(wire, off)
    of MetaPublicKey:
      if oplen == 32:
        for i in 0 ..< 32: result.publicKey.bytes[i] = wire[off + i]
    of MetaPriority:
      if oplen >= 1: result.priority = wire[off]
    else: discard
    off += oplen

# ── Async metadata handshake (StreamTransport for TCP) ───────────────────────

proc doClientHandshake*(transp: StreamTransport, crypto: RouterCrypto,
                        priority: byte = 0,
                        password: seq[byte] = @[]): Future[NodeId] {.async.} =
  var meta: seq[byte]
  try:
    meta = encodeMetadata(crypto, priority, password)
  except Exception:
    raise newException(ValueError, "encodeMetadata failed")
  discard await transp.write(meta).wait(chronos.milliseconds(HandshakeTimeoutMs))

  var hdr = newSeq[byte](6)
  await transp.readExactly(addr hdr[0], 6).wait(chronos.milliseconds(HandshakeTimeoutMs))

  if hdr[0] != byte('m') or hdr[1] != byte('e') or
     hdr[2] != byte('t') or hdr[3] != byte('a'):
    raise newException(ValueError, "invalid metadata preamble from remote")

  let bodyLen = int(readU16be(hdr, 4))
  var body = newSeq[byte](bodyLen)
  await transp.readExactly(addr body[0], bodyLen).wait(chronos.milliseconds(HandshakeTimeoutMs))

  var mwire = newSeq[byte](6 + bodyLen)
  copyMem(addr mwire[0], addr hdr[0], 6)
  copyMem(addr mwire[6], addr body[0], bodyLen)

  let remote = decodeMetadata(mwire)
  if remote.major != ProtocolVersionMajor or remote.minor != ProtocolVersionMinor:
    raise newException(ValueError, "incompatible remote version " &
      $remote.major & "." & $remote.minor)
  return remote.publicKey

proc doServerHandshake*(transp: StreamTransport, crypto: RouterCrypto,
                        priority: byte = 0,
                        password: seq[byte] = @[]): Future[NodeId] {.async.} =
  var hdr = newSeq[byte](6)
  await transp.readExactly(addr hdr[0], 6).wait(chronos.milliseconds(HandshakeTimeoutMs))

  if hdr[0] != byte('m') or hdr[1] != byte('e') or
     hdr[2] != byte('t') or hdr[3] != byte('a'):
    raise newException(ValueError, "invalid metadata preamble from remote")

  let bodyLen = int(readU16be(hdr, 4))
  var body = newSeq[byte](bodyLen)
  await transp.readExactly(addr body[0], bodyLen).wait(chronos.milliseconds(HandshakeTimeoutMs))

  var mwire = newSeq[byte](6 + bodyLen)
  copyMem(addr mwire[0], addr hdr[0], 6)
  copyMem(addr mwire[6], addr body[0], bodyLen)

  let remote = decodeMetadata(mwire)
  if remote.major != ProtocolVersionMajor or remote.minor != ProtocolVersionMinor:
    raise newException(ValueError, "incompatible remote version")

  var meta: seq[byte]
  try:
    meta = encodeMetadata(crypto, priority, password)
  except Exception:
    raise newException(ValueError, "encodeMetadata failed")
  discard await transp.write(meta).wait(chronos.milliseconds(HandshakeTimeoutMs))
  return remote.publicKey

# ── SOCKS5 client ───────────────────────────────────────────────────────────

type
  SocksAuth = object
    username: string
    password: string

proc parseSocksDest(destStr: string): tuple[host: string, port: int] =
  if destStr.startsWith("["):
    let close = destStr.find(']')
    if close < 0: raise newException(ValueError, "invalid SOCKS destination")
    result.host = destStr[1 ..< close]
    if close + 1 < destStr.len and destStr[close + 1] == ':':
      result.port = parseInt(destStr[close + 2 .. ^1])
    else:
      raise newException(ValueError, "SOCKS destination missing port")
  else:
    let colon = destStr.rfind(':')
    if colon < 0: raise newException(ValueError, "SOCKS destination missing port")
    result.host = destStr[0 ..< colon]
    result.port = parseInt(destStr[colon + 1 .. ^1])

proc socks5Connect*(transp: StreamTransport, destHost: string, destPort: int,
                    auth: SocksAuth = SocksAuth()): Future[void] {.async.} =
  var req: seq[byte]
  if auth.username.len > 0:
    req.add @[byte(0x05), 0x02, 0x00, 0x02]
  else:
    req.add @[byte(0x05), 0x01, 0x00]
  discard await transp.write(req).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  var resp = newSeq[byte](2)
  await transp.readExactly(addr resp[0], 2).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  if resp[0] != 0x05:
    raise newException(ValueError, "SOCKS5: invalid version in response")
  if resp[1] == 0x02:
    if auth.username.len > 255 or auth.password.len > 255:
      raise newException(ValueError, "SOCKS5: username/password too long")
    var authReq: seq[byte]
    authReq.add byte(0x01)
    authReq.add byte(auth.username.len)
    for c in auth.username: authReq.add byte(c)
    authReq.add byte(auth.password.len)
    for c in auth.password: authReq.add byte(c)
    discard await transp.write(authReq).wait(chronos.milliseconds(SocksConnectTimeoutMs))
    var authResp = newSeq[byte](2)
    await transp.readExactly(addr authResp[0], 2).wait(chronos.milliseconds(SocksConnectTimeoutMs))
    if authResp[1] != 0x00:
      raise newException(ValueError, "SOCKS5: authentication failed")
  elif resp[1] != 0x00:
    raise newException(ValueError, "SOCKS5: unsupported auth method " & $resp[1])
  var connectReq: seq[byte]
  connectReq.add byte(0x05)
  connectReq.add byte(0x01)
  connectReq.add byte(0x00)
  if destHost.contains(':'):
    connectReq.add byte(0x04)
    var ipBytes: array[16, byte]
    let groups = destHost.split(':')
    if groups.len != 8:
      raise newException(ValueError, "SOCKS5: unsupported IPv6 format")
    for i in 0 ..< 8:
      let g = parseHexInt(groups[i])
      ipBytes[i * 2] = byte(g shr 8)
      ipBytes[i * 2 + 1] = byte(g and 0xff)
    for b in ipBytes: connectReq.add b
  else:
    var isIpv4 = true
    var ipBytes: array[4, byte]
    let parts = destHost.split('.')
    if parts.len == 4:
      for i in 0 ..< 4:
        try: ipBytes[i] = byte(parseInt(parts[i]))
        except ValueError: isIpv4 = false; break
    else: isIpv4 = false
    if isIpv4:
      connectReq.add byte(0x01)
      for b in ipBytes: connectReq.add b
    else:
      if destHost.len > 255:
        raise newException(ValueError, "SOCKS5: domain name too long")
      connectReq.add byte(0x03)
      connectReq.add byte(destHost.len)
      for c in destHost: connectReq.add byte(c)
  connectReq.add byte((destPort shr 8) and 0xff)
  connectReq.add byte(destPort and 0xff)
  discard await transp.write(connectReq).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  var connectResp = newSeq[byte](4)
  await transp.readExactly(addr connectResp[0], 4).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  if connectResp[1] != 0x00:
    raise newException(ValueError, "SOCKS5: connect failed with code " & $connectResp[1])
  case connectResp[3]
  of 0x01:
    var rest = newSeq[byte](6)
    await transp.readExactly(addr rest[0], 6).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  of 0x04:
    var rest = newSeq[byte](18)
    await transp.readExactly(addr rest[0], 18).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  of 0x03:
    var lenBuf = newSeq[byte](1)
    await transp.readExactly(addr lenBuf[0], 1).wait(chronos.milliseconds(SocksConnectTimeoutMs))
    var rest = newSeq[byte](int(lenBuf[0]) + 2)
    await transp.readExactly(addr rest[0], rest.len).wait(chronos.milliseconds(SocksConnectTimeoutMs))
  else:
    raise newException(ValueError, "SOCKS5: unknown address type in response")

# ── Link Manager ─────────────────────────────────────────────────────────────

type
  LinkConfig* = object
    listenAddrs*: seq[string]
    peerUris*: seq[string]
    password*: seq[byte]

  LinkManager* = ref object
    config*: LinkConfig
    crypto*: RouterCrypto
    packetConn*: PacketConn
    servers*: seq[StreamServer]
    dialFuts*: seq[Future[void]]
    tlsBridges*: seq[TlsBridgeState]
    running*: bool

proc newLinkManager*(crypto: RouterCrypto, packetConn: PacketConn,
                     config: LinkConfig): LinkManager =
  result = LinkManager(
    config: config,
    crypto: crypto,
    packetConn: packetConn,
    running: false,
  )

proc resolveSni(parsed: PeerUri): string =
  if parsed.sni.len > 0:
    return parsed.sni
  let h = parsed.host
  if h.len > 0:
    var looksLikeIp = true
    for c in h:
      if c notin {'0'..'9', 'a'..'f', 'A'..'F', ':', '.'}:
        looksLikeIp = false
        break
    if not looksLikeIp:
      return h
  return ""

proc resolveHost(host: string): seq[string] =
  ## Resolve a hostname to IP addresses. Returns the host itself if it's already an IP.
  if host.contains(':'):
    return @[host]  # IPv6 literal
  let parts = host.split('.')
  var isIp = true
  if parts.len == 4:
    for p in parts:
      try: discard parseInt(p)
      except ValueError: isIp = false; break
  else:
    isIp = false
  if isIp:
    return @[host]
  # DNS resolution via Chronos — resolve and convert to string
  try:
    let addrs = resolveTAddress(host, Port(0))
    for a in addrs:
      let ipStr = $a
      # $TransportAddress includes port, strip it
      # Format is like "1.2.3.4:0" or "[::1]:0"
      if ipStr.startsWith("[") and ipStr.contains("]"):
        let close = ipStr.find(']')
        result.add(ipStr[1 ..< close])
      elif ipStr.contains(':'):
        let colon = ipStr.rfind(':')
        result.add(ipStr[0 ..< colon])
      else:
        result.add(host)
    if result.len == 0: result.add(host)
  except CatchableError:
    result.add(host)

proc dialTcpPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
  var backoffMs = 1000
  let maxBackoff = if parsed.maxBackoff > 0: parsed.maxBackoff * 1000
                   else: DefaultMaxBackoffMs
  let priority = parsed.priority
  let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                 else: manager.config.password

  while manager.running:
    try:
      let hosts = resolveHost(parsed.host)
      var connected = false
      for host in hosts:
        try:
          let address = initTAddress(host, parsed.port)
          let transp = await connect(address)
          try:
            let remoteKey = await doClientHandshake(transp, manager.crypto, priority, password)
            if remoteKey == manager.crypto.publicKey:
              transp.close()
              continue
            echo "connected to ", short(remoteKey), " via ", uri
            backoffMs = 1000
            connected = true
            await manager.packetConn.handleConn(remoteKey, transp, priority)
            echo "disconnected from ", short(remoteKey)
          except Exception as e:
            echo "handshake error with ", uri, ": ", e.msg
            try: transp.close()
            except Exception: discard
          break  # only try first resolved address per attempt
        except Exception:
          continue  # try next resolved address
      if not connected:
        echo "dial error ", uri, ": all addresses failed"
    except Exception as e:
      echo "dial error ", uri, ": ", e.msg
    await sleepAsync(chronos.milliseconds(backoffMs))
    backoffMs = min(backoffMs * 2, maxBackoff)

when defined(ssl):
  proc dialTlsPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
    ## Dial a TLS peer using OpenSSL thread bridge (supports TLS 1.3).
    var backoffMs = 1000
    let maxBackoff = if parsed.maxBackoff > 0: parsed.maxBackoff * 1000
                     else: DefaultMaxBackoffMs
    let priority = parsed.priority
    let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                   else: manager.config.password
    let sni = resolveSni(parsed)

    while manager.running:
      var bridgeState: TlsBridgeState = nil
      try:
        # Resolve DNS if needed
        let hosts = resolveHost(parsed.host)
        var connected = false
        for host in hosts:
          let bridgeResult = createTlsBridge(TlsBridgeConfig(
            host: host,
            port: parsed.port,
            sni: sni,
            timeoutMs: HandshakeTimeoutMs,
          ))
          if bridgeResult.isNone:
            continue  # try next address
          let (state, transp) = bridgeResult.get()
          bridgeState = state
          manager.tlsBridges.add(state)
          
          try:
            await sleepAsync(chronos.milliseconds(100))
            let remoteKey = await doClientHandshake(transp, manager.crypto, priority, password)
            if remoteKey == manager.crypto.publicKey:
              transp.close()
              state.close()
              continue
            echo "connected (TLS) to ", short(remoteKey), " via ", uri
            backoffMs = 1000
            connected = true
            await manager.packetConn.handleConn(remoteKey, transp, priority)
            echo "disconnected (TLS) from ", short(remoteKey)
          except Exception as e:
            echo "TLS+meta error with ", uri, ": ", e.msg
            try: transp.close()
            except Exception: discard
            state.close()
          break  # only try first resolved address per attempt
        
        if not connected and bridgeState == nil:
          echo "TLS dial error ", uri, ": all addresses failed"
      except Exception as e:
        echo "TLS dial error ", uri, ": ", e.msg
        if bridgeState != nil:
          bridgeState.close()
      
      await sleepAsync(chronos.milliseconds(backoffMs))
      backoffMs = min(backoffMs * 2, maxBackoff)
else:
  proc dialTlsPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
    echo "TLS not available (compile with -d:ssl for OpenSSL support): ", uri
    while manager.running:
      await sleepAsync(chronos.milliseconds(60000))

proc dialSocksPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
  var backoffMs = 1000
  let maxBackoff = if parsed.maxBackoff > 0: parsed.maxBackoff * 1000
                   else: DefaultMaxBackoffMs
  let priority = parsed.priority
  let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                 else: manager.config.password
  let useTls = parsed.kind == tkSocksTls
  let sni = resolveSni(parsed)
  let proxyPart = parsed.host
  let destPart = parsed.path
  var auth: SocksAuth
  var proxyAddr = proxyPart
  let atPos = proxyPart.find('@')
  if atPos >= 0:
    let userInfo = proxyPart[0 ..< atPos]
    proxyAddr = proxyPart[atPos + 1 .. ^1]
    let colonPos = userInfo.find(':')
    if colonPos >= 0:
      auth.username = userInfo[0 ..< colonPos]
      auth.password = userInfo[colonPos + 1 .. ^1]
    else:
      auth.username = userInfo
  let dest = parseSocksDest(destPart)

  while manager.running:
    try:
      let colonIdx = proxyAddr.rfind(':')
      if colonIdx < 0:
        raise newException(ValueError, "SOCKS proxy missing port: " & proxyAddr)
      let proxyHost = proxyAddr[0 ..< colonIdx]
      let proxyPort = parseInt(proxyAddr[colonIdx + 1 .. ^1])
      let address = initTAddress(proxyHost, proxyPort)
      let rawTransp = await connect(address)
      try:
        await socks5Connect(rawTransp, dest.host, dest.port, auth)
        when defined(ssl):
          if useTls:
            let destSni = if sni.len > 0: sni
                          elif dest.host.contains(':'): ""
                          else: resolveSni(PeerUri(host: dest.host, kind: tkTls))
            let bridgeResult = createTlsBridge(TlsBridgeConfig(
              host: dest.host, port: dest.port, sni: destSni,
              timeoutMs: HandshakeTimeoutMs,
            ))
            if bridgeResult.isNone:
              raise newException(ValueError, "SOCKS+TLS: bridge creation failed")
            let (tlsState, tlsTransp) = bridgeResult.get()
            manager.tlsBridges.add(tlsState)
            try:
              let remoteKey = await doClientHandshake(tlsTransp, manager.crypto, priority, password)
              if remoteKey == manager.crypto.publicKey:
                tlsTransp.close()
                tlsState.close()
                await sleepAsync(chronos.milliseconds(5000))
                continue
              echo "connected (SOCKS+TLS) to ", short(remoteKey), " via ", uri
              backoffMs = 1000
              await manager.packetConn.handleConn(remoteKey, tlsTransp, priority)
              echo "disconnected (SOCKS+TLS) from ", short(remoteKey)
            except Exception as e:
              echo "SOCKS+TLS error ", uri, ": ", e.msg
              try: tlsTransp.close()
              except Exception: discard
              tlsState.close()
          else:
            let remoteKey = await doClientHandshake(rawTransp, manager.crypto, priority, password)
            if remoteKey == manager.crypto.publicKey:
              rawTransp.close()
              await sleepAsync(chronos.milliseconds(5000))
              continue
            echo "connected (SOCKS) to ", short(remoteKey), " via ", uri
            backoffMs = 1000
            await manager.packetConn.handleConn(remoteKey, rawTransp, priority)
            echo "disconnected (SOCKS) from ", short(remoteKey)
        else:
          if useTls:
            echo "TLS not available (compile with -d:ssl): ", uri
            rawTransp.close()
            await sleepAsync(chronos.milliseconds(60000))
            continue
          let remoteKey = await doClientHandshake(rawTransp, manager.crypto, priority, password)
          if remoteKey == manager.crypto.publicKey:
            rawTransp.close()
            await sleepAsync(chronos.milliseconds(5000))
            continue
          echo "connected (SOCKS) to ", short(remoteKey), " via ", uri
          backoffMs = 1000
          await manager.packetConn.handleConn(remoteKey, rawTransp, priority)
          echo "disconnected (SOCKS) from ", short(remoteKey)
      except Exception as e:
        echo "SOCKS error ", uri, ": ", e.msg
        try: rawTransp.close()
        except Exception: discard
    except Exception as e:
      echo "SOCKS dial error ", uri, ": ", e.msg
    await sleepAsync(chronos.milliseconds(backoffMs))
    backoffMs = min(backoffMs * 2, maxBackoff)

proc dialWsPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
  ## Dial a WebSocket peer (ws:// or wss://).
  ## For wss://, uses the OpenSSL TLS bridge first, then WebSocket handshake.
  var backoffMs = 1000
  let maxBackoff = if parsed.maxBackoff > 0: parsed.maxBackoff * 1000
                   else: DefaultMaxBackoffMs
  let priority = parsed.priority
  let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                 else: manager.config.password
  let useTls = parsed.scheme in ["wss", "websocket"]
  let sni = resolveSni(parsed)
  let wsPath = if parsed.path.len > 0: parsed.path else: "/"

  while manager.running:
    try:
      when defined(ssl):
        var transp: StreamTransport
        var tlsState: TlsBridgeState = nil
        
        if useTls:
          # wss:// — TLS bridge then WS handshake
          let hosts = resolveHost(parsed.host)
          var bridgeOk = false
          for host in hosts:
            let bridgeResult = createTlsBridge(TlsBridgeConfig(
              host: host, port: parsed.port, sni: sni,
              timeoutMs: HandshakeTimeoutMs,
            ))
            if bridgeResult.isSome:
              let (state, t) = bridgeResult.get()
              tlsState = state
              transp = t
              manager.tlsBridges.add(state)
              bridgeOk = true
              break
          if not bridgeOk:
            raise newException(ValueError, "WSS: TLS bridge creation failed")
        else:
          # ws:// — plain TCP
          let hosts = resolveHost(parsed.host)
          var connected = false
          for host in hosts:
            try:
              let address = initTAddress(host, parsed.port)
              transp = await connect(address)
              connected = true
              break
            except Exception:
              continue
          if not connected:
            raise newException(ValueError, "WS: TCP connect failed")
        
        try:
          # WebSocket handshake
          await wsHandshake(transp, parsed.host, parsed.port, wsPath)
          
          # Yggdrasil metadata handshake
          let remoteKey = await doClientHandshake(transp, manager.crypto, priority, password)
          if remoteKey == manager.crypto.publicKey:
            transp.close()
            if tlsState != nil: tlsState.close()
            await sleepAsync(chronos.milliseconds(5000))
            continue
          
          let proto = if useTls: "WSS" else: "WS"
          echo "connected (", proto, ") to ", short(remoteKey), " via ", uri
          backoffMs = 1000
          await manager.packetConn.handleConn(remoteKey, transp, priority)
          echo "disconnected (", proto, ") from ", short(remoteKey)
        except Exception as e:
          let proto = if useTls: "WSS" else: "WS"
          echo proto, "+meta error with ", uri, ": ", e.msg
          try: transp.close()
          except Exception: discard
          if tlsState != nil: tlsState.close()
      else:
        if useTls:
          echo "WSS not available (compile with -d:ssl): ", uri
          await sleepAsync(chronos.milliseconds(60000))
          continue
        # Plain ws:// without SSL
        let hosts = resolveHost(parsed.host)
        var connected = false
        for host in hosts:
          try:
            let address = initTAddress(host, parsed.port)
            let transp = await connect(address)
            try:
              await wsHandshake(transp, parsed.host, parsed.port, wsPath)
              let remoteKey = await doClientHandshake(transp, manager.crypto, priority, password)
              if remoteKey == manager.crypto.publicKey:
                transp.close()
                continue
              echo "connected (WS) to ", short(remoteKey), " via ", uri
              backoffMs = 1000
              connected = true
              await manager.packetConn.handleConn(remoteKey, transp, priority)
              echo "disconnected (WS) from ", short(remoteKey)
            except Exception as e:
              echo "WS error ", uri, ": ", e.msg
              try: transp.close()
              except Exception: discard
            break
          except Exception:
            continue
        if not connected:
          echo "WS dial error ", uri, ": all addresses failed"
    except Exception as e:
      echo "WS dial error ", uri, ": ", e.msg
    
    await sleepAsync(chronos.milliseconds(backoffMs))
    backoffMs = min(backoffMs * 2, maxBackoff)

proc dialQuicPeer(manager: LinkManager, uri: string, parsed: PeerUri) {.async.} =
  ## Dial a QUIC peer using OpenSSL QUIC API via thread bridge.
  ## OpenSSL 3.5+ supports QUIC natively via the same API as TLS.
  var backoffMs = 1000
  let maxBackoff = if parsed.maxBackoff > 0: parsed.maxBackoff * 1000
                   else: DefaultMaxBackoffMs
  let priority = parsed.priority
  let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                 else: manager.config.password
  let sni = resolveSni(parsed)

  while manager.running:
    when defined(ssl):
      var bridgeState: TlsBridgeState = nil
      try:
        let hosts = resolveHost(parsed.host)
        var connected = false
        for host in hosts:
          # OpenSSL QUIC uses the same createTlsBridge but we need to
          # tell it to use QUIC. For now, the TLS bridge connects via TCP
          # and does TLS — QUIC needs UDP. This is a TODO.
          # As a workaround, some Yggdrasil QUIC peers also accept TLS on the same port.
          # We try TLS first as fallback.
          let bridgeResult = createTlsBridge(TlsBridgeConfig(
            host: host, port: parsed.port, sni: sni,
            timeoutMs: HandshakeTimeoutMs,
          ))
          if bridgeResult.isNone:
            continue
          let (state, transp) = bridgeResult.get()
          bridgeState = state
          manager.tlsBridges.add(state)
          
          try:
            await sleepAsync(chronos.milliseconds(100))
            let remoteKey = await doClientHandshake(transp, manager.crypto, priority, password)
            if remoteKey == manager.crypto.publicKey:
              transp.close()
              state.close()
              continue
            echo "connected (QUIC->TLS fallback) to ", short(remoteKey), " via ", uri
            backoffMs = 1000
            connected = true
            await manager.packetConn.handleConn(remoteKey, transp, priority)
            echo "disconnected (QUIC->TLS) from ", short(remoteKey)
          except Exception as e:
            echo "QUIC+meta error ", uri, ": ", e.msg
            try: transp.close()
            except Exception: discard
            state.close()
          break
        
        if not connected and bridgeState == nil:
          echo "QUIC dial error ", uri, ": all addresses failed"
      except Exception as e:
        echo "QUIC dial error ", uri, ": ", e.msg
        if bridgeState != nil: bridgeState.close()
    else:
      echo "QUIC not available (compile with -d:ssl for OpenSSL QUIC): ", uri
      await sleepAsync(chronos.milliseconds(60000))
    
    await sleepAsync(chronos.milliseconds(backoffMs))
    backoffMs = min(backoffMs * 2, maxBackoff)

proc start*(manager: LinkManager) {.async.} =
  manager.running = true
  for addrStr in manager.config.listenAddrs:
    try:
      let parsed = parsePeerUri(addrStr)
      let address = initTAddress(parsed.host, parsed.port)
      let password = if parsed.password.len > 0: parsed.password.mapIt(byte(it))
                     else: manager.config.password
      case parsed.kind
      of tkTcp:
        let server = createStreamServer(address,
          proc (server: StreamServer, remote: StreamTransport): Future[void] {.async: (raises: []).} =
            try:
              let remoteKey = await doServerHandshake(remote, manager.crypto, 0, password)
              if remoteKey == manager.crypto.publicKey:
                remote.close()
                return
              echo "incoming connection from ", short(remoteKey)
              asyncSpawn manager.packetConn.handleConn(remoteKey, remote)
            except Exception:
              try: remote.close()
              except Exception: discard
        )
        server.start()
        manager.servers.add(server)
        echo "listening on ", $address
      of tkTls:
        echo "TLS listener not yet implemented: ", addrStr
      else:
        echo "unsupported listen scheme: ", addrStr
    except Exception as e:
      echo "failed to listen on ", addrStr, ": ", e.msg

  for uri in manager.config.peerUris:
    try:
      let parsed = parsePeerUri(uri)
      case parsed.kind
      of tkTcp:
        manager.dialFuts.add(dialTcpPeer(manager, uri, parsed))
      of tkTls:
        manager.dialFuts.add(dialTlsPeer(manager, uri, parsed))
      of tkSocks, tkSocksTls:
        manager.dialFuts.add(dialSocksPeer(manager, uri, parsed))
      of tkQuic:
        manager.dialFuts.add(dialQuicPeer(manager, uri, parsed))
      of tkWebSocket:
        manager.dialFuts.add(dialWsPeer(manager, uri, parsed))
      of tkUnix:
        echo "Unix peers not yet supported: ", uri
      of tkUdp:
        echo "UDP peers not yet supported: ", uri
    except Exception as e:
      echo "invalid peer URI ", uri, ": ", e.msg

proc stop*(manager: LinkManager) {.async.} =
  manager.running = false
  for server in manager.servers:
    server.stop()
    server.close()
  manager.servers.setLen(0)
  when defined(ssl):
    for bridge in manager.tlsBridges:
      bridge.close()
    manager.tlsBridges.setLen(0)

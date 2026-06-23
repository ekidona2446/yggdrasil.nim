## Persistent TCP link runner for pure-Nim Ironwood.
##
## This module attaches `RouterState` to a real TCP peer socket: it performs the
## yggdrasil-go metadata handshake using libsodium-backed Ed25519 keys, then
## continuously reads Ironwood frames, dispatches them through `RouterState`, and
## writes resulting frames back to the peer.

import std/[net, os, osproc, strutils, times, options]
import ../core/[types, peermanager]
import ../crypto/sodium
import ../util/bytes as ubytes
import ../util/ipnet as yipnet
import ./wire
import ./router
import ./routerstate

type
  LinkLogKind* = enum llInfo, llFrame, llEvent, llError

  LinkLog* = object
    kind*: LinkLogKind
    message*: string

  LinkRunConfig* = object
    uri*: string
    keyFile*: string
    seconds*: int
    target*: string
    timeoutMs*: int

const
  ProtocolVersionMajor = 0'u16
  ProtocolVersionMinor = 5'u16
  MetaVersionMajor = 0'u16
  MetaVersionMinor = 1'u16
  MetaPublicKey = 2'u16
  MetaPriority = 3'u16

proc putU16be(buf: var seq[byte], x: uint16) =
  buf.add byte((x shr 8) and 0xff)
  buf.add byte(x and 0xff)

proc readU16be(data: openArray[byte], off: int): uint16 =
  if off + 2 > data.len: raise newException(ValueError, "short uint16")
  (uint16(data[off]) shl 8) or uint16(data[off + 1])

proc rawBytes(data: openArray[byte]): string =
  result = newString(data.len)
  for i, b in data: result[i] = char(b)

proc recvExact(sock: Socket, n: int, timeoutMs: int): seq[byte] =
  while result.len < n:
    let chunk = sock.recv(n - result.len, timeoutMs)
    if chunk.len == 0: raise newException(IOError, "socket closed")
    for c in chunk: result.add byte(ord(c) and 0xff)

proc saveRouterCrypto*(path: string, crypto: RouterCrypto) =
  writeFile(path, "# yggdrasil.nim Ed25519/libsodium key\nsecretKey=" & ubytes.toHex(crypto.secretKey) & "\n")

proc loadOrCreateRouterCrypto*(path: string): RouterCrypto =
  if fileExists(path):
    for raw in readFile(path).splitLines():
      let line = raw.strip()
      if line.startsWith("secretKey="):
        let bytes = ubytes.fromHex(line.split("=", 1)[1])
        if bytes.len != 64: raise newException(ValueError, "invalid Ed25519 secret key length")
        var sk: Ed25519SecretKey
        for i in 0 ..< 64: sk[i] = bytes[i]
        return routerCryptoFromSodium(sk)
    raise newException(ValueError, "key file missing secretKey= line")
  try:
    result = newRouterCrypto()
  except CatchableError:
    ## Fallback key generation for config/bootstrap on systems without libsodium.
    ## The resulting key file is usable once libsodium is available at runtime.
    let pem = path & ".tmp.pem"
    let der = path & ".tmp.der"
    let pubder = path & ".tmp.pub.der"
    defer:
      for f in [pem, der, pubder]:
        if fileExists(f): removeFile(f)
    var res = execCmdEx("openssl genpkey -algorithm Ed25519 -out " & pem.quoteShell)
    if res.exitCode != 0: raise newException(OSError, "openssl genpkey failed: " & res.output)
    res = execCmdEx("openssl pkey -in " & pem.quoteShell & " -outform DER -out " & der.quoteShell)
    if res.exitCode != 0: raise newException(OSError, "openssl private DER failed: " & res.output)
    res = execCmdEx("openssl pkey -in " & pem.quoteShell & " -pubout -outform DER -out " & pubder.quoteShell)
    if res.exitCode != 0: raise newException(OSError, "openssl public DER failed: " & res.output)
    let d = readFile(der)
    let p = readFile(pubder)
    if d.len < 32 or p.len < 32: raise newException(ValueError, "OpenSSL produced short Ed25519 key")
    for i in 0 ..< 32:
      result.secretKey[i] = byte(ord(d[d.len - 32 + i]) and 0xff)
      result.secretKey[32 + i] = byte(ord(p[p.len - 32 + i]) and 0xff)
      result.publicKey.bytes[i] = result.secretKey[32 + i]
  saveRouterCrypto(path, result)

proc encodeMetadata*(crypto: RouterCrypto, priority: byte = 0, password: openArray[byte] = []): seq[byte] =
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
  if wire[0] != byte(ord('m')) or wire[1] != byte(ord('e')) or wire[2] != byte(ord('t')) or wire[3] != byte(ord('a')):
    raise newException(ValueError, "invalid metadata preamble")
  let hlen = int(readU16be(wire, 4))
  if hlen != wire.len - 6: raise newException(ValueError, "metadata length mismatch")
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

proc readFrame(sock: Socket, timeoutMs: int): Option[seq[byte]] =
  var value: uint64 = 0
  var shift = 0
  var raw: seq[byte]
  for _ in 0 ..< 10:
    let bseq = sock.recvExact(1, timeoutMs)
    let b = bseq[0]
    raw.add b
    if shift >= 63 and b > 1'u8: return none(seq[byte])
    value = value or (uint64(b and 0x7f) shl shift)
    if (b and 0x80'u8) == 0:
      if value == 0 or value > 1_048_576'u64: return none(seq[byte])
      let body = sock.recvExact(int(value), timeoutMs)
      for x in body: raw.add x
      return some(raw)
    shift += 7
  none(seq[byte])

proc parseYggdrasilIPv6(s: string): IPv6Address =
  var host = s.strip()
  if host.startsWith("[") and host.endsWith("]"): host = host[1 ..< host.len - 1]
  let ip = yipnet.parseIpAddress(host)
  if ip.family != yipnet.ifIPv6: raise newException(ValueError, "expected IPv6 address")
  for i in 0 ..< 16: result[i] = ip.bytes[i]

proc sendActions(sock: Socket, actions: seq[FrameAction]) =
  for a in actions:
    sock.send(rawBytes(a.frame))

proc logEvent(logs: var seq[LinkLog], ev: RouterEvent) =
  logs.add LinkLog(kind: llEvent, message: $ev.kind & " " & ev.detail)

proc runTcpIronwoodLink*(cfg: LinkRunConfig): seq[LinkLog] =
  var crypto = loadOrCreateRouterCrypto(cfg.keyFile)
  var state = initRouterState(crypto)
  let peerUri = parsePeerUri(cfg.uri)
  if peerUri.kind != tkTcp: raise newException(ValueError, "persistent Ironwood runner currently supports tcp:// only")
  let domain = if peerUri.host.contains(":"): AF_INET6 else: AF_INET
  var sock = newSocket(domain = domain, buffered = false)
  defer: sock.close()
  let timeoutMs = if cfg.timeoutMs > 0: cfg.timeoutMs else: 7000
  sock.connect(peerUri.host, Port(peerUri.port), timeout = timeoutMs)
  result.add LinkLog(kind: llInfo, message: "connected tcp " & cfg.uri)

  let meta = encodeMetadata(crypto)
  sock.send(rawBytes(meta))
  let hdr = sock.recvExact(6, timeoutMs)
  let hlen = int(readU16be(hdr, 4))
  let body = sock.recvExact(hlen, timeoutMs)
  var mwire = hdr
  for b in body: mwire.add b
  let remote = decodeMetadata(mwire)
  if remote.major != ProtocolVersionMajor or remote.minor != ProtocolVersionMinor:
    raise newException(ValueError, "incompatible remote version " & $remote.major & "." & $remote.minor)
  result.add LinkLog(kind: llInfo, message: "meta remote=" & short(remote.publicKey) & " addr=" & toIPv6String(deriveYggAddress(remote.publicKey)))

  var step = state.addPeer(remote.publicKey)
  sock.sendActions(step.outbound)
  for ev in step.events: result.logEvent(ev)

  if cfg.target.len > 0:
    let target = parseYggdrasilIPv6(cfg.target)
    let dest = keyPrefixForYggAddress(target)
    let lookup = state.sendLookup(dest)
    sock.sendActions(lookup.outbound)
    result.add LinkLog(kind: llInfo, message: "lookup target=" & toIPv6String(target) & " keyPrefix=" & short(dest) & " frames=" & $lookup.outbound.len)

  let until = if cfg.seconds > 0: epochTime() + float(cfg.seconds) else: 1.0e300
  var lastKeepalive = epochTime()
  var lastMaintenance = epochTime()
  while epochTime() < until:
    if epochTime() - lastKeepalive > 10:
      sock.send(rawBytes(encodeFrame(iwKeepAlive, [])))
      lastKeepalive = epochTime()
    if epochTime() - lastMaintenance > 5:
      let mt = state.maintenance()
      sock.sendActions(mt.outbound)
      for ev in mt.events: result.logEvent(ev)
      result.add LinkLog(kind: llInfo, message: "maintenance frames=" & $mt.outbound.len)
      lastMaintenance = epochTime()
    try:
      let fb = sock.readFrame(1000)
      if fb.isNone: continue
      let frame = decodeFrame(fb.get())
      if frame.isNone:
        result.add LinkLog(kind: llError, message: "decode frame failed")
        continue
      result.add LinkLog(kind: llFrame, message: "recv " & $frame.get().packetType & " payload=" & $frame.get().payload.len)
      let pid = state.peerIdFor(remote.publicKey)
      if pid.isNone: continue
      let st = state.handleFrameBytes(pid.get(), fb.get())
      sock.sendActions(st.outbound)
      for ev in st.events: result.logEvent(ev)
      for d in st.deliveries:
        result.add LinkLog(kind: llInfo, message: "delivery source=" & short(d.source) & " bytes=" & $d.data.len)
    except TimeoutError:
      discard
    except CatchableError as e:
      result.add LinkLog(kind: llError, message: e.msg)
      break

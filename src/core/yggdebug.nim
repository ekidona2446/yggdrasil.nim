## Debug-only Yggdrasil metadata handshake support.
##
## This is NOT the full Yggdrasil data plane. It implements the initial
## yggdrasil-go `meta` exchange for TCP-family peers so we can verify that a
## public peer socket is not merely open but speaks the expected Yggdrasil link
## handshake. After the metadata exchange, yggdrasil-go switches to the Ironwood
## encrypted network/session layer.
##
## Reuses wire helpers from ironwood/asynclink (putU16be/readU16be) and core
## types (deriveYggAddress, ipv6Parse, keyPrefixForYggAddress) to avoid
## duplicating protocol constants.

import std/[net, os, osproc, strutils, times, options]
import ./types
import ./peermanager
import ../util/bytes
import ../util/ipnet as ipnet
import ../ironwood/wire
import ../ironwood/asynclink

type
  YggHandshakeResult* = object
    uri*: string
    ok*: bool
    error*: string
    localPublicKey*: NodeId
    remotePublicKey*: NodeId
    remoteAddress*: IPv6Address
    remoteMajor*: uint16
    remoteMinor*: uint16
    remotePriority*: byte

const
  ProtocolVersionMajor* = 0'u16
  ProtocolVersionMinor* = 5'u16
  MetaVersionMajor = 0'u16
  MetaVersionMinor = 1'u16
  MetaPublicKey = 2'u16
  MetaPriority = 3'u16

proc rawBytesToString(data: openArray[byte]): string =
  result = newString(data.len)
  for i, b in data: result[i] = char(b)

proc readFileBytes(path: string): seq[byte] =
  let s = readFile(path)
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(ord(c) and 0xff)

proc writeFileBytes(path: string, data: openArray[byte]) =
  writeFile(path, rawBytesToString(data))

proc runOpenSsl(args: seq[string]) =
  let res = execCmdEx("openssl " & args.join(" "))
  if res.exitCode != 0:
    raise newException(OSError, "openssl failed: openssl " & args.join(" ") & "\n" & res.output)

proc tempPath(prefix, ext: string): string =
  getTempDir() / (prefix & "-" & $getCurrentProcessId() & "-" & ($epochTime()).replace(".", "") & ext)

proc ensureDebugEd25519Key*(pemPath: string) =
  if fileExists(pemPath): return
  createDir(parentDir(pemPath))
  runOpenSsl(@["genpkey", "-algorithm", "Ed25519", "-out", pemPath.quoteShell])

proc opensslPublicKeyRaw*(pemPath: string): Bytes32 =
  ensureDebugEd25519Key(pemPath)
  let derPath = tempPath("yggdrasil-pub", ".der")
  defer:
    if fileExists(derPath): removeFile(derPath)
  runOpenSsl(@["pkey", "-in", pemPath.quoteShell, "-pubout", "-outform", "DER", "-out", derPath.quoteShell])
  let der = readFileBytes(derPath)
  if der.len < 32: raise newException(ValueError, "short Ed25519 public-key DER")
  for i in 0 ..< 32:
    result[i] = der[der.len - 32 + i]

proc opensslBlake2b512(data: openArray[byte]): seq[byte] =
  let inPath = tempPath("yggdrasil-blake-in", ".bin")
  let outPath = tempPath("yggdrasil-blake-out", ".bin")
  defer:
    if fileExists(inPath): removeFile(inPath)
    if fileExists(outPath): removeFile(outPath)
  writeFileBytes(inPath, data)
  runOpenSsl(@["dgst", "-blake2b512", "-binary", "-out", outPath.quoteShell, inPath.quoteShell])
  result = readFileBytes(outPath)
  if result.len != 64: raise newException(ValueError, "unexpected BLAKE2b-512 length")

proc opensslEd25519SignRaw(pemPath: string, data: openArray[byte]): seq[byte] =
  let inPath = tempPath("yggdrasil-sign-in", ".bin")
  let outPath = tempPath("yggdrasil-sign-out", ".bin")
  defer:
    if fileExists(inPath): removeFile(inPath)
    if fileExists(outPath): removeFile(outPath)
  writeFileBytes(inPath, data)
  runOpenSsl(@["pkeyutl", "-sign", "-rawin", "-inkey", pemPath.quoteShell, "-in", inPath.quoteShell, "-out", outPath.quoteShell])
  result = readFileBytes(outPath)
  if result.len != 64: raise newException(ValueError, "unexpected Ed25519 signature length")

proc encodeMetadata*(pemPath: string, priority: byte = 0): tuple[publicKey: NodeId, bytes: seq[byte]] =
  result.publicKey = NodeId(bytes: opensslPublicKeyRaw(pemPath))
  var body: seq[byte]
  body.putU16be(MetaVersionMajor)
  body.putU16be(2)
  body.putU16be(ProtocolVersionMajor)
  body.putU16be(MetaVersionMinor)
  body.putU16be(2)
  body.putU16be(ProtocolVersionMinor)
  body.putU16be(MetaPublicKey)
  body.putU16be(32)
  for b in result.publicKey.bytes: body.add b
  body.putU16be(MetaPriority)
  body.putU16be(1)
  body.add priority
  let hash = opensslBlake2b512(result.publicKey.bytes)
  let sig = opensslEd25519SignRaw(pemPath, hash)
  for b in sig: body.add b
  result.bytes = @[byte(ord('m')), byte(ord('e')), byte(ord('t')), byte(ord('a'))]
  result.bytes.putU16be(uint16(body.len))
  for b in body: result.bytes.add b

proc recvExact(sock: Socket, n: int, timeoutMs: int): seq[byte] =
  result = newSeq[byte]()
  while result.len < n:
    let chunk = sock.recv(n - result.len, timeoutMs)
    if chunk.len == 0: raise newException(IOError, "socket closed during handshake")
    for c in chunk: result.add byte(ord(c) and 0xff)

proc decodeMetadata*(wire: openArray[byte]): tuple[publicKey: NodeId, major, minor: uint16, priority: byte] =
  if wire.len < 70: raise newException(ValueError, "metadata too short")
  if wire[0] != byte(ord('m')) or wire[1] != byte(ord('e')) or wire[2] != byte(ord('t')) or wire[3] != byte(ord('a')):
    raise newException(ValueError, "invalid Yggdrasil metadata preamble")
  let hlen = int(readU16be(wire, 4))
  if hlen != wire.len - 6: raise newException(ValueError, "metadata length mismatch")
  let siglessEnd = wire.len - 64
  var off = 6
  while off + 4 <= siglessEnd:
    let op = readU16be(wire, off)
    let oplen = int(readU16be(wire, off + 2))
    off += 4
    if off + oplen > siglessEnd: break
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
    else:
      discard
    off += oplen
  if result.publicKey.bytes == default(Bytes32):
    raise newException(ValueError, "metadata missing public key")

proc performYggdrasilTcpMetadataHandshake*(uri: string, keyPemPath: string, timeoutMs = 7000, priority: byte = 0): YggHandshakeResult =
  result.uri = uri
  try:
    let peer = parsePeerUri(uri)
    if peer.kind != tkTcp:
      raise newException(ValueError, "debug metadata handshake currently supports tcp:// peers only")
    let local = encodeMetadata(keyPemPath, priority)
    result.localPublicKey = local.publicKey
    let domain = if peer.host.contains(":"): AF_INET6 else: AF_INET
    var sock = newSocket(domain = domain, buffered = false)
    defer: sock.close()
    sock.connect(peer.host, Port(peer.port), timeout = timeoutMs)
    sock.send(rawBytesToString(local.bytes))
    let hdr = sock.recvExact(6, timeoutMs)
    let hlen = int(readU16be(hdr, 4))
    if hlen < 64 or hlen > 4096: raise newException(ValueError, "invalid remote metadata length: " & $hlen)
    let body = sock.recvExact(hlen, timeoutMs)
    var wire = hdr
    for b in body: wire.add b
    let remote = decodeMetadata(wire)
    result.remotePublicKey = remote.publicKey
    result.remoteMajor = remote.major
    result.remoteMinor = remote.minor
    result.remotePriority = remote.priority
    result.remoteAddress = deriveYggAddress(remote.publicKey)
    if remote.major != ProtocolVersionMajor or remote.minor != ProtocolVersionMinor:
      raise newException(ValueError, "incompatible remote protocol version " & $remote.major & "." & $remote.minor)
    result.ok = true
  except CatchableError as e:
    result.ok = false
    result.error = e.msg

proc summary*(r: YggHandshakeResult): string =
  if r.ok:
    "OK " & r.uri & " remoteKey=" & toHex(r.remotePublicKey) & " remoteAddr=" &
      toIPv6String(r.remoteAddress) & " version=" & $r.remoteMajor & "." & $r.remoteMinor &
      " priority=" & $r.remotePriority
  else:
    "FAIL " & r.uri & " error=" & r.error

proc readWireUvarint(sock: Socket, timeoutMs: int): Option[tuple[value: uint64, bytes: seq[byte]]] =
  var value: uint64 = 0
  var shift = 0
  var raw: seq[byte]
  for _ in 0 ..< 10:
    let bseq = sock.recvExact(1, timeoutMs)
    let b = bseq[0]
    raw.add b
    if shift >= 63 and b > 1'u8: return none(tuple[value: uint64, bytes: seq[byte]])
    value = value or (uint64(b and 0x7f) shl shift)
    if (b and 0x80'u8) == 0: return some((value, raw))
    shift += 7
  none(tuple[value: uint64, bytes: seq[byte]])

proc sig64FromSeq(s: seq[byte]): array[64, byte] =
  if s.len != 64: raise newException(ValueError, "expected 64-byte signature")
  for i in 0 ..< 64: result[i] = s[i]

proc routerSigBytes(node, parent: NodeId, seq, nonce, port: uint64): seq[byte] =
  for b in node.bytes: result.add b
  for b in parent.bytes: result.add b
  encodeUvarint(seq, result)
  encodeUvarint(nonce, result)
  encodeUvarint(port, result)

proc probeYggdrasilTcpIronwood*(uri: string, keyPemPath: string, seconds = 5, timeoutMs = 7000,
                                targetAddress = ""): seq[string] =
  ## Debug post-meta Ironwood frame probe. It sends our valid metadata, reads the
  ## remote metadata, sends a KeepAlive frame, then logs any frames received for a
  ## short time. This is not yet a functioning router/session, but it verifies the
  ## stream transitions from `meta` to Ironwood framing.
  let peer = parsePeerUri(uri)
  if peer.kind != tkTcp:
    raise newException(ValueError, "Ironwood probe currently supports tcp:// peers only")
  let local = encodeMetadata(keyPemPath)
  let domain = if peer.host.contains(":"): AF_INET6 else: AF_INET
  var sock = newSocket(domain = domain, buffered = false)
  defer: sock.close()
  sock.connect(peer.host, Port(peer.port), timeout = timeoutMs)
  sock.send(rawBytesToString(local.bytes))
  let hdr = sock.recvExact(6, timeoutMs)
  let hlen = int(readU16be(hdr, 4))
  let body = sock.recvExact(hlen, timeoutMs)
  var metaWire = hdr
  for b in body: metaWire.add b
  let remote = decodeMetadata(metaWire)
  let remoteAddr = deriveYggAddress(remote.publicKey)
  result.add "META remoteKey=" & toHex(remote.publicKey) & " remoteAddr=" & toIPv6String(remoteAddr) &
    " version=" & $remote.major & "." & $remote.minor

  let keepalive = encodeFrame(iwKeepAlive, [])
  sock.send(rawBytesToString(keepalive))
  result.add "SENT KeepAlive frame bytes=" & $keepalive.len

  let ourReqSeq = 1'u64
  let ourReqNonce = uint64(epochTime() * 1_000_000) xor readU64be(hash256(local.publicKey.bytes, "yggdrasil-debug-sigreq"), 0)
  let ourReqFrame = encodeFrame(iwProtoSigReq, encodeSigReq(SigReq(seq: ourReqSeq, nonce: ourReqNonce)))
  sock.send(rawBytesToString(ourReqFrame))
  result.add "SENT SigReq seq=" & $ourReqSeq & " nonce=" & $ourReqNonce & " bytes=" & $ourReqFrame.len

  if targetAddress.len > 0:
    let targetIp = ipv6Parse(targetAddress)
    let destKey = keyPrefixForYggAddress(targetIp)
    let lookup = PathLookup(source: local.publicKey, dest: destKey, fromPath: @[])
    let frame = encodeFrame(iwProtoPathLookup, encodePathLookup(lookup))
    sock.send(rawBytesToString(frame))
    result.add "SENT PathLookup target=" & toIPv6String(targetIp) & " destKeyPrefix=" & short(destKey) & " bytes=" & $frame.len

  let deadline = epochTime() + float(seconds)
  var frameCount = 0
  while epochTime() < deadline:
    try:
      let lenDec = sock.readWireUvarint(1000)
      if lenDec.isNone: break
      let length = int(lenDec.get().value)
      if length <= 0 or length > 1_048_576:
        result.add "BAD frame length=" & $length
        break
      let content = sock.recvExact(length, timeoutMs)
      var whole = lenDec.get().bytes
      for b in content: whole.add b
      let f = decodeFrame(whole)
      if f.isSome:
        inc frameCount
        result.add "RECV " & $f.get().packetType & " payload=" & $f.get().payload.len & " frameBytes=" & $whole.len
        if f.get().packetType == iwProtoSigReq:
          let req = decodeSigReq(f.get().payload)
          if req.isSome:
            let port = 1'u64
            let sig = opensslEd25519SignRaw(keyPemPath, routerSigBytes(remote.publicKey, local.publicKey, req.get().seq, req.get().nonce, port)).sig64FromSeq()
            let res = SigResFull(seq: req.get().seq, nonce: req.get().nonce, port: port, parentSignature: sig)
            let frame = encodeFrame(iwProtoSigRes, encodeSigResFull(res))
            sock.send(rawBytesToString(frame))
            result.add "SENT SigRes seq=" & $req.get().seq & " nonce=" & $req.get().nonce & " port=" & $port & " bytes=" & $frame.len
        elif f.get().packetType == iwProtoSigRes:
          let res = decodeSigResFull(f.get().payload)
          if res.isSome and res.get().value.seq == ourReqSeq and res.get().value.nonce == ourReqNonce:
            let sr = res.get().value
            let localSig = opensslEd25519SignRaw(keyPemPath, routerSigBytes(local.publicKey, remote.publicKey, sr.seq, sr.nonce, sr.port)).sig64FromSeq()
            let ann = Announce(key: local.publicKey, parent: remote.publicKey,
                               sigRes: sr, signature: localSig)
            let frame = encodeFrame(iwProtoAnnounce, encodeAnnounce(ann))
            sock.send(rawBytesToString(frame))
            result.add "SENT Announce parent=" & short(remote.publicKey) & " port=" & $sr.port & " bytes=" & $frame.len
        elif f.get().packetType == iwProtoPathNotify:
          let n = decodePathNotify(f.get().payload)
          if n.isSome:
            result.add "RECV PathNotify source=" & short(n.get().source) & " dest=" & short(n.get().dest) & " pathLen=" & $n.get().path.len & " infoPathLen=" & $n.get().info.path.len & " watermark=" & $n.get().watermark
        elif f.get().packetType == iwProtoPathBroken:
          let b = decodePathBroken(f.get().payload)
          if b.isSome:
            result.add "RECV PathBroken source=" & short(b.get().source) & " dest=" & short(b.get().dest) & " pathLen=" & $b.get().path.len & " watermark=" & $b.get().watermark
      else:
        result.add "BAD undecodable frame bytes=" & $whole.len
        break
    except CatchableError as e:
      result.add "READ_STOP " & e.msg
      break
  result.add "frames=" & $frameCount

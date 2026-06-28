## Ironwood wire protocol primitives.
##
## Ported from Yggdrasil-ng's `crates/ironwood/src/wire.rs` and yggdrasil-go's
## current Ironwood framing rules. This is the first pure-Nim post-`meta`
## building block: frame length uvarints, packet types, path encoding, bloom
## compression, and traffic frame layout.

import std/options
import ../core/types

const
  BloomFilterFlags* = 16
  BloomFilterU64s* = 128

type
  PacketType* = enum
    Dummy = 0,
    KeepAlive = 1,
    ProtoSigReq = 2,
    ProtoSigRes = 3,
    ProtoAnnounce = 4,
    ProtoBloomFilter = 5,
    ProtoPathLookup = 6,
    ProtoPathNotify = 7,
    ProtoPathBroken = 8,
    Traffic = 9

  PeerPort* = uint64
  Path* = seq[PeerPort]

  Frame* = object
    packetType*: PacketType
    payload*: seq[byte]
    consumed*: int

  SigReq* = object
    seq*: uint64
    nonce*: uint64

  SigRes* = object
    seq*: uint64
    nonce*: uint64
    signature*: array[64, byte]

  TrafficPacket* = object
    path*: Path
    fromPath*: Path
    source*: NodeId
    dest*: NodeId
    watermark*: uint64
    payload*: seq[byte]

proc toPacketType*(b: byte): Option[PacketType] =
  case b
  of 0: some(Dummy)
  of 1: some(KeepAlive)
  of 2: some(ProtoSigReq)
  of 3: some(ProtoSigRes)
  of 4: some(ProtoAnnounce)
  of 5: some(ProtoBloomFilter)
  of 6: some(ProtoPathLookup)
  of 7: some(ProtoPathNotify)
  of 8: some(ProtoPathBroken)
  of 9: some(Traffic)
  else: none(PacketType)

proc encodeUvarint*(value: uint64, outBuf: var seq[byte]) =
  var v = value
  while true:
    var b = byte(v and 0x7f)
    v = v shr 7
    if v != 0: b = b or 0x80'u8
    outBuf.add b
    if v == 0: break

proc encodeUvarint*(value: uint64): seq[byte] =
  encodeUvarint(value, result)

proc decodeUvarint*(data: openArray[byte], offset = 0): Option[tuple[value: uint64, consumed: int]] =
  var value: uint64 = 0
  var shift = 0
  var i = offset
  while i < data.len:
    let b = data[i]
    if shift >= 63 and b > 1'u8: return none(tuple[value: uint64, consumed: int])
    value = value or (uint64(b and 0x7f) shl shift)
    inc i
    if (b and 0x80'u8) == 0:
      return some((value, i - offset))
    shift += 7
    if i - offset >= 10: return none(tuple[value: uint64, consumed: int])
  none(tuple[value: uint64, consumed: int])

proc uvarintSize*(value: uint64): int =
  var v = value
  result = 1
  while v >= 0x80'u64:
    v = v shr 7
    inc result

proc encodePath*(path: openArray[PeerPort], outBuf: var seq[byte]) =
  for p in path: encodeUvarint(p, outBuf)
  encodeUvarint(0, outBuf)

proc encodePath*(path: openArray[PeerPort]): seq[byte] =
  encodePath(path, result)

proc pathSize*(path: openArray[PeerPort]): int =
  for p in path: result += uvarintSize(p)
  result += uvarintSize(0)

proc decodePath*(data: openArray[byte], offset = 0): Option[tuple[path: Path, consumed: int]] =
  var off = offset
  var path: Path
  while true:
    let d = decodeUvarint(data, off)
    if d.isNone: return none(tuple[path: Path, consumed: int])
    let (value, n) = d.get()
    off += n
    if value == 0: return some((path, off - offset))
    path.add value

proc encodeFrame*(packetType: PacketType, payload: openArray[byte]): seq[byte] =
  let contentLen = uint64(1 + payload.len)
  result = newSeqOfCap[byte](uvarintSize(contentLen) + int(contentLen))
  encodeUvarint(contentLen, result)
  result.add byte(packetType)
  for b in payload: result.add b

proc decodeFrame*(data: openArray[byte], offset = 0): Option[Frame] =
  let lenDec = decodeUvarint(data, offset)
  if lenDec.isNone: return none(Frame)
  let (length64, lenBytes) = lenDec.get()
  if length64 > uint64(high(int)): return none(Frame)
  let length = int(length64)
  if length <= 0: return none(Frame)
  let start = offset + lenBytes
  if data.len < start + length: return none(Frame)
  let pt = toPacketType(data[start])
  if pt.isNone: return none(Frame)
  var payload: seq[byte]
  for i in start + 1 ..< start + length:
    payload.add data[i]
  some(Frame(packetType: pt.get(), payload: payload, consumed: lenBytes + length))

proc readNodeId(data: openArray[byte], off: var int): Option[NodeId] =
  if off + 32 > data.len: return none(NodeId)
  var id: NodeId
  for i in 0 ..< 32: id.bytes[i] = data[off + i]
  off += 32
  some(id)

proc encodeSigReq*(s: SigReq): seq[byte] =
  encodeUvarint(s.seq, result)
  encodeUvarint(s.nonce, result)

proc decodeSigReq*(payload: openArray[byte]): Option[SigReq] =
  let a = decodeUvarint(payload, 0)
  if a.isNone: return none(SigReq)
  let b = decodeUvarint(payload, a.get().consumed)
  if b.isNone: return none(SigReq)
  some(SigReq(seq: a.get().value, nonce: b.get().value))

proc encodeTrafficPayload*(t: TrafficPacket): seq[byte] =
  encodePath(t.path, result)
  encodePath(t.fromPath, result)
  for b in t.source.bytes: result.add b
  for b in t.dest.bytes: result.add b
  encodeUvarint(t.watermark, result)
  for b in t.payload: result.add b

proc encodeTrafficFrame*(t: TrafficPacket): seq[byte] = encodeFrame(Traffic, encodeTrafficPayload(t))

proc decodeTraffic*(payload: openArray[byte]): Option[TrafficPacket] =
  var off = 0
  let p = decodePath(payload, off)
  if p.isNone: return none(TrafficPacket)
  off += p.get().consumed
  let f = decodePath(payload, off)
  if f.isNone: return none(TrafficPacket)
  off += f.get().consumed
  let src = readNodeId(payload, off)
  if src.isNone: return none(TrafficPacket)
  let dst = readNodeId(payload, off)
  if dst.isNone: return none(TrafficPacket)
  let wm = decodeUvarint(payload, off)
  if wm.isNone: return none(TrafficPacket)
  off += wm.get().consumed
  var rest: seq[byte]
  for i in off ..< payload.len: rest.add payload[i]
  some(TrafficPacket(path: p.get().path, fromPath: f.get().path, source: src.get(),
               dest: dst.get(), watermark: wm.get().value, payload: rest))

proc encodeBloom*(data: array[BloomFilterU64s, uint64]): seq[byte] =
  var flags0: array[BloomFilterFlags, byte]
  var flags1: array[BloomFilterFlags, byte]
  var keep: seq[uint64]
  for idx, u in data:
    if u == 0:
      flags0[idx div 8] = flags0[idx div 8] or (0x80'u8 shr (idx mod 8))
    elif u == high(uint64):
      flags1[idx div 8] = flags1[idx div 8] or (0x80'u8 shr (idx mod 8))
    else:
      keep.add u
  for b in flags0: result.add b
  for b in flags1: result.add b
  for u in keep:
    for shift in countdown(56, 0, 8):
      result.add byte((u shr shift) and 0xff'u64)

proc decodeBloom*(payload: openArray[byte]): Option[array[BloomFilterU64s, uint64]] =
  if payload.len < BloomFilterFlags * 2: return none(array[BloomFilterU64s, uint64])
  var bloomOut: array[BloomFilterU64s, uint64]
  var off = BloomFilterFlags * 2
  for idx in 0 ..< BloomFilterU64s:
    let f0 = payload[idx div 8] and (0x80'u8 shr (idx mod 8))
    let f1 = payload[BloomFilterFlags + idx div 8] and (0x80'u8 shr (idx mod 8))
    if f0 != 0 and f1 != 0: return none(array[BloomFilterU64s, uint64])
    elif f0 != 0: bloomOut[idx] = 0
    elif f1 != 0: bloomOut[idx] = high(uint64)
    else:
      if off + 8 > payload.len: return none(array[BloomFilterU64s, uint64])
      var u: uint64 = 0
      for i in 0 ..< 8: u = (u shl 8) or uint64(payload[off + i])
      bloomOut[idx] = u
      off += 8
  if off != payload.len: return none(array[BloomFilterU64s, uint64])
  some(bloomOut)

type
  SigResFull* = object
    seq*: uint64
    nonce*: uint64
    port*: PeerPort
    parentSignature*: array[64, byte]

  Announce* = object
    key*: NodeId
    parent*: NodeId
    sigRes*: SigResFull
    signature*: array[64, byte]

  PathLookup* = object
    source*: NodeId
    dest*: NodeId
    fromPath*: Path

  PathNotifyInfo* = object
    seq*: uint64
    path*: Path
    signature*: array[64, byte]

  PathNotify* = object
    path*: Path
    watermark*: uint64
    source*: NodeId
    dest*: NodeId
    info*: PathNotifyInfo

  PathBroken* = object
    path*: Path
    watermark*: uint64
    source*: NodeId
    dest*: NodeId

proc appendNodeId(outBuf: var seq[byte], id: NodeId) =
  for b in id.bytes: outBuf.add b

proc readSignature(data: openArray[byte], off: var int): Option[array[64, byte]] =
  if off + 64 > data.len: return none(array[64, byte])
  var sig: array[64, byte]
  for i in 0 ..< 64: sig[i] = data[off + i]
  off += 64
  some(sig)

proc encodeSigResFull*(s: SigResFull): seq[byte] =
  encodeUvarint(s.seq, result)
  encodeUvarint(s.nonce, result)
  encodeUvarint(s.port, result)
  for b in s.parentSignature: result.add b

proc decodeSigResFull*(payload: openArray[byte], offset = 0): Option[tuple[value: SigResFull, consumed: int]] =
  var off = offset
  let seq = decodeUvarint(payload, off)
  if seq.isNone: return none(tuple[value: SigResFull, consumed: int])
  off += seq.get().consumed
  let nonce = decodeUvarint(payload, off)
  if nonce.isNone: return none(tuple[value: SigResFull, consumed: int])
  off += nonce.get().consumed
  let port = decodeUvarint(payload, off)
  if port.isNone: return none(tuple[value: SigResFull, consumed: int])
  off += port.get().consumed
  let sig = readSignature(payload, off)
  if sig.isNone: return none(tuple[value: SigResFull, consumed: int])
  some((SigResFull(seq: seq.get().value, nonce: nonce.get().value,
                   port: port.get().value, parentSignature: sig.get()), off - offset))

proc encodeAnnounce*(a: Announce): seq[byte] =
  result.appendNodeId(a.key)
  result.appendNodeId(a.parent)
  for b in encodeSigResFull(a.sigRes): result.add b
  for b in a.signature: result.add b

proc decodeAnnounce*(payload: openArray[byte]): Option[Announce] =
  var off = 0
  let key = readNodeId(payload, off)
  if key.isNone: return none(Announce)
  let parent = readNodeId(payload, off)
  if parent.isNone: return none(Announce)
  let sr = decodeSigResFull(payload, off)
  if sr.isNone: return none(Announce)
  off += sr.get().consumed
  let sig = readSignature(payload, off)
  if sig.isNone: return none(Announce)
  if off != payload.len: return none(Announce)
  some(Announce(key: key.get(), parent: parent.get(), sigRes: sr.get().value, signature: sig.get()))

proc encodePathLookup*(p: PathLookup): seq[byte] =
  result.appendNodeId(p.source)
  result.appendNodeId(p.dest)
  encodePath(p.fromPath, result)

proc decodePathLookup*(payload: openArray[byte]): Option[PathLookup] =
  var off = 0
  let src = readNodeId(payload, off)
  if src.isNone: return none(PathLookup)
  let dst = readNodeId(payload, off)
  if dst.isNone: return none(PathLookup)
  let path = decodePath(payload, off)
  if path.isNone: return none(PathLookup)
  off += path.get().consumed
  if off != payload.len: return none(PathLookup)
  some(PathLookup(source: src.get(), dest: dst.get(), fromPath: path.get().path))

proc encodePathNotifyInfo*(i: PathNotifyInfo): seq[byte] =
  encodeUvarint(i.seq, result)
  encodePath(i.path, result)
  for b in i.signature: result.add b

proc decodePathNotifyInfo(payload: openArray[byte], offset: int): Option[tuple[value: PathNotifyInfo, consumed: int]] =
  var off = offset
  let seq = decodeUvarint(payload, off)
  if seq.isNone: return none(tuple[value: PathNotifyInfo, consumed: int])
  off += seq.get().consumed
  let path = decodePath(payload, off)
  if path.isNone: return none(tuple[value: PathNotifyInfo, consumed: int])
  off += path.get().consumed
  let sig = readSignature(payload, off)
  if sig.isNone: return none(tuple[value: PathNotifyInfo, consumed: int])
  some((PathNotifyInfo(seq: seq.get().value, path: path.get().path, signature: sig.get()), off - offset))

proc encodePathNotify*(p: PathNotify): seq[byte] =
  encodePath(p.path, result)
  encodeUvarint(p.watermark, result)
  result.appendNodeId(p.source)
  result.appendNodeId(p.dest)
  for b in encodePathNotifyInfo(p.info): result.add b

proc decodePathNotify*(payload: openArray[byte]): Option[PathNotify] =
  var off = 0
  let path = decodePath(payload, off)
  if path.isNone: return none(PathNotify)
  off += path.get().consumed
  let wm = decodeUvarint(payload, off)
  if wm.isNone: return none(PathNotify)
  off += wm.get().consumed
  let src = readNodeId(payload, off)
  if src.isNone: return none(PathNotify)
  let dst = readNodeId(payload, off)
  if dst.isNone: return none(PathNotify)
  let info = decodePathNotifyInfo(payload, off)
  if info.isNone: return none(PathNotify)
  off += info.get().consumed
  if off != payload.len: return none(PathNotify)
  some(PathNotify(path: path.get().path, watermark: wm.get().value, source: src.get(), dest: dst.get(), info: info.get().value))

proc encodePathBroken*(p: PathBroken): seq[byte] =
  encodePath(p.path, result)
  encodeUvarint(p.watermark, result)
  result.appendNodeId(p.source)
  result.appendNodeId(p.dest)

proc decodePathBroken*(payload: openArray[byte]): Option[PathBroken] =
  var off = 0
  let path = decodePath(payload, off)
  if path.isNone: return none(PathBroken)
  off += path.get().consumed
  let wm = decodeUvarint(payload, off)
  if wm.isNone: return none(PathBroken)
  off += wm.get().consumed
  let src = readNodeId(payload, off)
  if src.isNone: return none(PathBroken)
  let dst = readNodeId(payload, off)
  if dst.isNone: return none(PathBroken)
  if off != payload.len: return none(PathBroken)
  some(PathBroken(path: path.get().path, watermark: wm.get().value, source: src.get(), dest: dst.get()))

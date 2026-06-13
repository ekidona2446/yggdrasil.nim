## Minimal persistent Ironwood peer state machine.
##
## This layer turns decoded Ironwood frames into outbound frames and events. It is
## intentionally transport-agnostic; a TCP/TLS/QUIC task should feed frames in and
## write returned frames out. It already handles KeepAlive, SigReq/SigRes,
## Announce validation/storage, BloomFilter storage, PathNotify/PathBroken events,
## and correct per-SigReq RTT timing.

import std/[options, tables]
import ../core/types
import ./wire
import ./router

type
  PeerEventKind* = enum
    peKeepAlive,
    peSigReqReceived,
    peSigResReceived,
    peAnnounceAccepted,
    peAnnounceRejected,
    peBloomReceived,
    pePathNotifyReceived,
    pePathBrokenReceived,
    peDecodeError

  PeerEvent* = object
    kind*: PeerEventKind
    detail*: string
    rttMs*: Option[int64]
    announceKey*: Option[NodeId]
    pathSource*: Option[NodeId]
    pathDest*: Option[NodeId]

  PeerStep* = object
    outbound*: seq[seq[byte]]
    events*: seq[PeerEvent]

  IronwoodPeer* = object
    id*: PeerId
    remoteKey*: NodeId
    remotePort*: PeerPort
    localPort*: PeerPort
    crypto*: RouterCrypto
    rtt*: RttTracker
    nextSigReqSeq*: uint64
    lastSigReqSeq*: uint64
    lastSigReqNonce*: uint64
    announces*: Table[NodeId, RouterAnnounce]
    bloom*: array[BloomFilterU64s, uint64]
    haveBloom*: bool

proc initIronwoodPeer*(id: PeerId, remoteKey: NodeId, crypto: RouterCrypto,
                       localPort: PeerPort = 1): IronwoodPeer =
  IronwoodPeer(id: id, remoteKey: remoteKey, remotePort: 0, localPort: localPort,
               crypto: crypto, rtt: initRttTracker(), nextSigReqSeq: 1,
               announces: initTable[NodeId, RouterAnnounce]())

proc addEvent(step: var PeerStep, kind: PeerEventKind, detail = "") =
  step.events.add PeerEvent(kind: kind, detail: detail)

proc makeKeepAlive*(): seq[byte] = encodeFrame(iwKeepAlive, [])

proc makeSigReq*(p: var IronwoodPeer, nonce: uint64): seq[byte] =
  let seq = p.nextSigReqSeq
  inc p.nextSigReqSeq
  p.lastSigReqSeq = seq
  p.lastSigReqNonce = nonce
  p.rtt.markSigReqSent(p.id)
  encodeFrame(iwProtoSigReq, encodeSigReq(SigReq(seq: seq, nonce: nonce)))

proc makePathLookup*(p: IronwoodPeer, dest: NodeId, fromPath: Path = @[]): seq[byte] =
  encodeFrame(iwProtoPathLookup, encodePathLookup(PathLookup(source: p.crypto.publicKey, dest: dest, fromPath: fromPath)))

proc handleSigReq(p: IronwoodPeer, req: SigReq): seq[byte] =
  let sig = p.crypto.signSigRes(p.remoteKey, p.crypto.publicKey, req.seq, req.nonce, p.localPort)
  let res = SigResFull(seq: req.seq, nonce: req.nonce, port: p.localPort, parentSignature: sig)
  encodeFrame(iwProtoSigRes, encodeSigResFull(res))

proc handleSigRes(p: var IronwoodPeer, res: SigResFull, step: var PeerStep) =
  p.remotePort = res.port
  var ev = PeerEvent(kind: peSigResReceived, detail: "port=" & $res.port)
  if res.seq == p.lastSigReqSeq and res.nonce == p.lastSigReqNonce:
    ev.rttMs = p.rtt.handleSigResReceived(p.id)
    let ann = makeChildAnnounce(p.crypto, p.remoteKey, res.seq, res.nonce, res.port, res.parentSignature.toSig64())
    step.outbound.add encodeFrame(iwProtoAnnounce, encodeAnnounce(ann.toWire()))
  step.events.add ev

proc handleAnnounce(p: var IronwoodPeer, payload: openArray[byte], step: var PeerStep) =
  let annWire = decodeAnnounce(payload)
  if annWire.isNone:
    step.addEvent(peDecodeError, "bad announce")
    return
  let ann = fromWireAnnounce(annWire.get())
  if ann.check():
    p.announces[ann.key] = ann
    step.events.add PeerEvent(kind: peAnnounceAccepted, detail: "parent=" & short(ann.parent), announceKey: some(ann.key))
  else:
    step.events.add PeerEvent(kind: peAnnounceRejected, announceKey: some(ann.key))

proc handleFrame*(p: var IronwoodPeer, frame: Frame): PeerStep =
  case frame.packetType
  of iwKeepAlive:
    result.addEvent(peKeepAlive)
  of iwProtoSigReq:
    let req = decodeSigReq(frame.payload)
    if req.isNone:
      result.addEvent(peDecodeError, "bad sigreq")
    else:
      result.events.add PeerEvent(kind: peSigReqReceived, detail: "seq=" & $req.get().seq)
      result.outbound.add p.handleSigReq(req.get())
  of iwProtoSigRes:
    let res = decodeSigResFull(frame.payload)
    if res.isNone:
      result.addEvent(peDecodeError, "bad sigres")
    else:
      p.handleSigRes(res.get().value, result)
  of iwProtoAnnounce:
    p.handleAnnounce(frame.payload, result)
  of iwProtoBloomFilter:
    let b = decodeBloom(frame.payload)
    if b.isNone:
      result.addEvent(peDecodeError, "bad bloom")
    else:
      p.bloom = b.get()
      p.haveBloom = true
      result.addEvent(peBloomReceived)
  of iwProtoPathLookup:
    let l = decodePathLookup(frame.payload)
    if l.isNone:
      result.addEvent(peDecodeError, "bad pathlookup")
    else:
      result.addEvent(pePathNotifyReceived, "lookup source=" & short(l.get().source) & " dest=" & short(l.get().dest))
  of iwProtoPathNotify:
    let n = decodePathNotify(frame.payload)
    if n.isNone:
      result.addEvent(peDecodeError, "bad pathnotify")
    else:
      result.events.add PeerEvent(kind: pePathNotifyReceived, pathSource: some(n.get().source), pathDest: some(n.get().dest), detail: "pathLen=" & $n.get().path.len)
  of iwProtoPathBroken:
    let b = decodePathBroken(frame.payload)
    if b.isNone:
      result.addEvent(peDecodeError, "bad pathbroken")
    else:
      result.events.add PeerEvent(kind: pePathBrokenReceived, pathSource: some(b.get().source), pathDest: some(b.get().dest), detail: "pathLen=" & $b.get().path.len)
  of iwDummy, iwTraffic:
    discard

proc handleFrameBytes*(p: var IronwoodPeer, data: openArray[byte]): PeerStep =
  let frame = decodeFrame(data)
  if frame.isNone:
    result.addEvent(peDecodeError, "bad frame")
  else:
    result = p.handleFrame(frame.get())

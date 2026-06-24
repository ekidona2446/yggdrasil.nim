## Ironwood encrypted session primitives.
##
## Implements session Init/Ack packet construction and parsing plus traffic
## encryption/decryption helpers. This maps to Yggdrasil-ng
## `crates/ironwood/src/encrypted/session.rs`; the session manager/router is the
## next layer above this module.

import std/[options, times, tables]
import ../crypto/sodium
import ../core/types
import ./wire

const
  SessionTypeDummy* = 0'u8
  SessionTypeInit* = 1'u8
  SessionTypeAck* = 2'u8
  SessionTypeTraffic* = 3'u8
  SessionInitSize* = 1 + 32 + 16 + 64 + 32 + 32 + 8 + 8

type
  EdKeyPair* = object
    publicKey*: Ed25519PublicKey
    secretKey*: Ed25519SecretKey

  SessionInit* = object
    current*: Curve25519PublicKey
    next*: Curve25519PublicKey
    keySeq*: uint64
    seq*: uint64

  DecodedSessionPacket* = object
    msgType*: byte
    init*: SessionInit

  TrafficHeader* = object
    localKeySeq*: uint64
    remoteKeySeq*: uint64
    nonce*: uint64
    encryptedOffset*: int

proc toNodeId*(pk: Ed25519PublicKey): NodeId =
  for i in 0 ..< 32: result.bytes[i] = pk[i]

proc toEdPublic*(id: NodeId): Ed25519PublicKey =
  for i in 0 ..< 32: result[i] = id.bytes[i]

proc newEdKeyPair*(): EdKeyPair =
  let kp = newEd25519Keypair()
  EdKeyPair(publicKey: kp.pk, secretKey: kp.sk)

proc unixSeq*(): uint64 = uint64(epochTime().int64)

proc writeU64be(buf: var seq[byte], x: uint64) =
  for i in countdown(7, 0): buf.add byte((x shr (i * 8)) and 0xff'u64)

proc readU64be(data: openArray[byte], off: int): uint64 =
  if off + 8 > data.len: raise newException(ValueError, "short u64")
  for i in 0 ..< 8: result = (result shl 8) or uint64(data[off + i])

proc sessionSignBytes(fromPub, current, next: Curve25519PublicKey, keySeq, seq: uint64): seq[byte] =
  for b in fromPub: result.add b
  for b in current: result.add b
  for b in next: result.add b
  result.writeU64be(keySeq)
  result.writeU64be(seq)

proc encrypt*(init: SessionInit, ourEd: EdKeyPair, toEdPub: Ed25519PublicKey,
              msgType = SessionTypeInit, preimage: openArray[byte] = []): seq[byte] =
  let eph = newCurve25519Keypair()
  let toCurve = edPublicToCurve25519(toEdPub)
  let sigBytes = sessionSignBytes(eph.pk, init.current, init.next, init.keySeq, init.seq)
  var signed: seq[byte]
  for b in preimage: signed.add b
  for b in sigBytes: signed.add b
  let sig = signDetached(ourEd.secretKey, signed)

  var payload: seq[byte]
  for b in sig: payload.add b
  for b in init.current: payload.add b
  for b in init.next: payload.add b
  payload.writeU64be(init.keySeq)
  payload.writeU64be(init.seq)

  let shared = precompute(toCurve, eph.sk)
  let ciphertext = boxSealAfterPrecompute(payload, nonceForU64(0), shared)
  result.add msgType
  for b in eph.pk: result.add b
  for b in ciphertext: result.add b

proc decryptSessionInit*(data: openArray[byte], ourCurveSk: Curve25519SecretKey,
                         fromEdPub: Ed25519PublicKey, preimage: openArray[byte] = []): Option[DecodedSessionPacket] =
  if data.len != SessionInitSize: return none(DecodedSessionPacket)
  if data[0] notin {SessionTypeInit, SessionTypeAck}: return none(DecodedSessionPacket)
  var eph: Curve25519PublicKey
  for i in 0 ..< 32: eph[i] = data[1 + i]
  var ciphertext: seq[byte]
  for i in 33 ..< data.len: ciphertext.add data[i]
  let shared = precompute(eph, ourCurveSk)
  var payload: seq[byte]
  try:
    payload = boxOpenAfterPrecompute(ciphertext, nonceForU64(0), shared)
  except CatchableError:
    return none(DecodedSessionPacket)
  if payload.len != 64 + 32 + 32 + 8 + 8: return none(DecodedSessionPacket)
  var sig: Signature64
  var current, next: Curve25519PublicKey
  for i in 0 ..< 64: sig[i] = payload[i]
  for i in 0 ..< 32: current[i] = payload[64 + i]
  for i in 0 ..< 32: next[i] = payload[96 + i]
  let keySeq = readU64be(payload, 128)
  let seq = readU64be(payload, 136)
  let sigBytes = sessionSignBytes(eph, current, next, keySeq, seq)
  var signed: seq[byte]
  for b in preimage: signed.add b
  for b in sigBytes: signed.add b
  if not verifyDetached(fromEdPub, signed, sig): return none(DecodedSessionPacket)
  some(DecodedSessionPacket(msgType: data[0], init: SessionInit(current: current, next: next, keySeq: keySeq, seq: seq)))

proc parseTrafficHeader*(data: openArray[byte]): Option[TrafficHeader] =
  if data.len < 1 or data[0] != SessionTypeTraffic: return none(TrafficHeader)
  var off = 1
  let a = decodeUvarint(data, off)
  if a.isNone: return none(TrafficHeader)
  off += a.get().consumed
  let b = decodeUvarint(data, off)
  if b.isNone: return none(TrafficHeader)
  off += b.get().consumed
  let c = decodeUvarint(data, off)
  if c.isNone: return none(TrafficHeader)
  off += c.get().consumed
  some(TrafficHeader(localKeySeq: a.get().value, remoteKeySeq: b.get().value,
                     nonce: c.get().value, encryptedOffset: off))

proc encryptTraffic*(localKeySeq, remoteKeySeq, nonce: uint64, nextPub: Curve25519PublicKey,
                     payload: openArray[byte], theirCurrent: Curve25519PublicKey,
                     ourSendSk: Curve25519SecretKey): seq[byte] =
  result.add SessionTypeTraffic
  encodeUvarint(localKeySeq, result)
  encodeUvarint(remoteKeySeq, result)
  encodeUvarint(nonce, result)
  var inner: seq[byte]
  for b in nextPub: inner.add b
  for b in payload: inner.add b
  let shared = precompute(theirCurrent, ourSendSk)
  let ciphertext = boxSealAfterPrecompute(inner, nonceForU64(nonce), shared)
  for b in ciphertext: result.add b

proc decryptTraffic*(data: openArray[byte], theirCurrent: Curve25519PublicKey,
                     ourRecvSk: Curve25519SecretKey): Option[tuple[header: TrafficHeader, nextPub: Curve25519PublicKey, payload: seq[byte]]] =
  let h = parseTrafficHeader(data)
  if h.isNone: return none(tuple[header: TrafficHeader, nextPub: Curve25519PublicKey, payload: seq[byte]])
  var ciphertext: seq[byte]
  for i in h.get().encryptedOffset ..< data.len: ciphertext.add data[i]
  let shared = precompute(theirCurrent, ourRecvSk)
  var inner: seq[byte]
  try:
    inner = boxOpenAfterPrecompute(ciphertext, nonceForU64(h.get().nonce), shared)
  except CatchableError:
    return none(tuple[header: TrafficHeader, nextPub: Curve25519PublicKey, payload: seq[byte]])
  if inner.len < 32: return none(tuple[header: TrafficHeader, nextPub: Curve25519PublicKey, payload: seq[byte]])
  var nextPub: Curve25519PublicKey
  for i in 0 ..< 32: nextPub[i] = inner[i]
  var plain: seq[byte]
  for i in 32 ..< inner.len: plain.add inner[i]
  some((h.get(), nextPub, plain))

# ---------------------------------------------------------------------------
# Minimal session manager
# ---------------------------------------------------------------------------

type
  SessionInfo* = object
    seq*: uint64
    remoteKeySeq*: uint64
    current*: Curve25519PublicKey
    next*: Curve25519PublicKey
    localKeySeq*: uint64
    recvPriv*: Curve25519SecretKey
    recvPub*: Curve25519PublicKey
    sendPriv*: Curve25519SecretKey
    sendPub*: Curve25519PublicKey
    nextPriv*: Curve25519SecretKey
    nextPub*: Curve25519PublicKey
    recvNonce*: uint64
    sendNonce*: uint64
    nextSendNonce*: uint64
    nextRecvNonce*: uint64
    lastActivity*: Time

  SessionBuffer* = object
    data*: seq[byte]
    hasData*: bool
    init*: SessionInit
    currentPriv*: Curve25519SecretKey
    nextPriv*: Curve25519SecretKey

  OutActionKind* = enum oaSendToInner, oaDeliver

  OutAction* = object
    kind*: OutActionKind
    dest*: Ed25519PublicKey
    source*: Ed25519PublicKey
    data*: seq[byte]

  SessionManager* = object
    local*: EdKeyPair
    localCurveSk*: Curve25519SecretKey
    sessions*: Table[Ed25519PublicKey, SessionInfo]
    buffers*: Table[Ed25519PublicKey, SessionBuffer]

proc newSessionInfo*(current, next: Curve25519PublicKey, seq: uint64): SessionInfo =
  let recv = newCurve25519Keypair()
  let send = newCurve25519Keypair()
  let nxt = newCurve25519Keypair()
  SessionInfo(seq: (if seq == 0'u64: high(uint64) else: seq - 1'u64), remoteKeySeq: 0, current: current, next: next,
              localKeySeq: 0, recvPriv: recv.sk, recvPub: recv.pk,
              sendPriv: send.sk, sendPub: send.pk,
              nextPriv: nxt.sk, nextPub: nxt.pk,
              lastActivity: getTime())

proc handleUpdate*(s: var SessionInfo, init: SessionInit) =
  s.current = init.current
  s.next = init.next
  s.seq = init.seq
  s.remoteKeySeq = init.keySeq
  s.recvPub = s.sendPub
  s.recvPriv = s.sendPriv
  s.sendPub = s.nextPub
  s.sendPriv = s.nextPriv
  let nxt = newCurve25519Keypair()
  s.nextPub = nxt.pk
  s.nextPriv = nxt.sk
  inc s.localKeySeq
  s.recvNonce = 0
  s.nextRecvNonce = 0
  s.nextSendNonce = 0
  s.lastActivity = getTime()

proc doSend*(s: var SessionInfo, msg: openArray[byte]): seq[byte] =
  inc s.sendNonce
  result = encryptTraffic(s.localKeySeq, s.remoteKeySeq, s.sendNonce, s.nextPub,
                          msg, s.current, s.sendPriv)
  s.lastActivity = getTime()

proc ratchet(s: var SessionInfo; remoteNextPub: Curve25519PublicKey) =
  ## Rotate both remote and local key epochs after decrypting a message from the
  ## remote's "next" key. Matches Rust/Yggdrasil-ng's maybe_ratchet_on_recv.
  s.current = s.next
  s.next = remoteNextPub
  inc s.remoteKeySeq
  s.recvPriv = s.sendPriv
  s.recvPub = s.sendPub
  s.sendPriv = s.nextPriv
  s.sendPub = s.nextPub
  let nxt = newCurve25519Keypair()
  s.nextPriv = nxt.sk
  s.nextPub = nxt.pk
  inc s.localKeySeq
  s.recvNonce = 0
  s.nextSendNonce = 0
  s.nextRecvNonce = 0

proc doRecv*(s: var SessionInfo, msg: openArray[byte]): Option[seq[byte]] =
  let h = parseTrafficHeader(msg)
  if h.isNone: return none(seq[byte])
  let hh = h.get()
  var dec: Option[tuple[header: TrafficHeader, nextPub: Curve25519PublicKey, payload: seq[byte]]]
  if hh.localKeySeq == s.remoteKeySeq and hh.remoteKeySeq + 1 == s.localKeySeq and hh.nonce > s.recvNonce:
    dec = decryptTraffic(msg, s.current, s.recvPriv)
    if dec.isSome: s.recvNonce = hh.nonce
  elif hh.localKeySeq == s.remoteKeySeq + 1 and hh.remoteKeySeq == s.localKeySeq and hh.nonce > s.nextSendNonce:
    dec = decryptTraffic(msg, s.next, s.sendPriv)
    if dec.isSome:
      s.nextSendNonce = hh.nonce
      s.ratchet(dec.get().nextPub)
  elif hh.localKeySeq == s.remoteKeySeq + 1 and hh.remoteKeySeq + 1 == s.localKeySeq and hh.nonce > s.nextRecvNonce:
    dec = decryptTraffic(msg, s.next, s.recvPriv)
    if dec.isSome:
      s.nextRecvNonce = hh.nonce
      s.ratchet(dec.get().nextPub)
  else:
    return none(seq[byte])
  if dec.isNone: return none(seq[byte])
  s.lastActivity = getTime()
  some(dec.get().payload)

proc initSessionManager*(local: EdKeyPair): SessionManager =
  SessionManager(local: local, localCurveSk: edSecretToCurve25519(local.secretKey),
                 sessions: initTable[Ed25519PublicKey, SessionInfo](),
                 buffers: initTable[Ed25519PublicKey, SessionBuffer]())

proc createSessionFromInit(m: var SessionManager, fromKey: Ed25519PublicKey, init: SessionInit): tuple[buffer: Option[seq[byte]], info: SessionInfo] =
  result.info = newSessionInfo(init.current, init.next, init.seq)
  if m.buffers.hasKey(fromKey):
    let buf = m.buffers[fromKey]
    result.info.sendPub = buf.init.current
    result.info.sendPriv = buf.currentPriv
    result.info.nextPub = buf.init.next
    result.info.nextPriv = buf.nextPriv
    if buf.hasData: result.buffer = some(buf.data)
    m.buffers.del(fromKey)

proc writeTo*(m: var SessionManager, dest: Ed25519PublicKey, msg: openArray[byte]): seq[OutAction] =
  if m.sessions.hasKey(dest):
    var s = m.sessions[dest]
    let data = s.doSend(msg)
    m.sessions[dest] = s
    return @[OutAction(kind: oaSendToInner, dest: dest, data: data)]
  var buf: SessionBuffer
  if m.buffers.hasKey(dest): buf = m.buffers[dest]
  else:
    let cur = newCurve25519Keypair()
    let nxt = newCurve25519Keypair()
    buf = SessionBuffer(init: SessionInit(current: cur.pk, next: nxt.pk, keySeq: 0, seq: unixSeq()),
                        currentPriv: cur.sk, nextPriv: nxt.sk)
  buf.data = newSeq[byte](msg.len)
  for i in 0 ..< msg.len: buf.data[i] = msg[i]
  buf.hasData = true
  m.buffers[dest] = buf
  @[OutAction(kind: oaSendToInner, dest: dest, data: buf.init.encrypt(m.local, dest, SessionTypeInit))]

proc handleData*(m: var SessionManager, fromKey: Ed25519PublicKey, data: openArray[byte]): seq[OutAction] =
  if data.len == 0: return @[]
  case data[0]
  of SessionTypeInit:
    let init = decryptSessionInit(data, m.localCurveSk, fromKey)
    stderr.writeLine "[session] Init from ", short(toNodeId(fromKey)), " decryptOk=", init.isSome
    if init.isNone: return @[]
    var made = m.createSessionFromInit(fromKey, init.get().init)
    var info = made.info
    let ack = SessionInit(current: info.sendPub, next: info.nextPub, keySeq: info.localKeySeq, seq: unixSeq())
    m.sessions[fromKey] = info
    # IMPORTANT: Send Ack BEFORE buffered data, so peer can set up session first
    result.add OutAction(kind: oaSendToInner, dest: fromKey, data: ack.encrypt(m.local, fromKey, SessionTypeAck))
    if made.buffer.isSome:
      result.add OutAction(kind: oaSendToInner, dest: fromKey, data: info.doSend(made.buffer.get()))
  of SessionTypeAck:
    let ack = decryptSessionInit(data, m.localCurveSk, fromKey)
    stderr.writeLine "[session] Ack from ", short(toNodeId(fromKey)), " decryptOk=", ack.isSome
    if ack.isNone: return @[]
    if m.sessions.hasKey(fromKey):
      var info = m.sessions[fromKey]
      if ack.get().init.seq > info.seq: info.handleUpdate(ack.get().init)
      m.sessions[fromKey] = info
    else:
      var made = m.createSessionFromInit(fromKey, ack.get().init)
      if ack.get().init.seq > made.info.seq: made.info.handleUpdate(ack.get().init)
      m.sessions[fromKey] = made.info
      # Send buffered data if any (but do NOT send another Ack back!)
      if made.buffer.isSome:
        result.add OutAction(kind: oaSendToInner, dest: fromKey, data: made.info.doSend(made.buffer.get()))
  of SessionTypeTraffic:
    if not m.sessions.hasKey(fromKey): return @[]
    var info = m.sessions[fromKey]
    let plain = info.doRecv(data)
    m.sessions[fromKey] = info
    stderr.writeLine "[session] Traffic from ", short(toNodeId(fromKey)), " decryptOk=", plain.isSome
    if plain.isSome: result.add OutAction(kind: oaDeliver, source: fromKey, data: plain.get())
  else:
    discard

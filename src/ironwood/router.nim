## Minimal Ironwood router signing primitives.
##
## This module does not yet implement the full CRDT router. It provides the
## signature-compatible pieces needed by the peer layer: SigReq/SigRes signing,
## RouterAnnounce creation/verification, and PathNotifyInfo signing.

import std/[os, strutils]
import ../core/types
import ../crypto/sodium
import ../util/bytes
import ./wire

type
  RouterCrypto* = object
    publicKey*: NodeId
    secretKey*: Ed25519SecretKey

  RouterAnnounce* = object
    key*: NodeId
    parent*: NodeId
    seq*: uint64
    nonce*: uint64
    port*: PeerPort
    parentSignature*: Signature64
    signature*: Signature64

proc toEdPublic(id: NodeId): Ed25519PublicKey =
  for i in 0 ..< 32: result[i] = id.bytes[i]

proc toSig64*(a: array[64, byte]): Signature64 =
  for i in 0 ..< 64: result[i] = a[i]

proc toArr64*(a: Signature64): array[64, byte] =
  for i in 0 ..< 64: result[i] = a[i]

proc routerCryptoFromEd25519*(sk: Ed25519SecretKey): RouterCrypto =
  ## Ed25519 secret key layout is seed || public key (64 bytes).
  result.secretKey = sk
  for i in 0 ..< 32: result.publicKey.bytes[i] = sk[32 + i]

proc newRouterCrypto*(): RouterCrypto =
  let kp = newEd25519Keypair()
  routerCryptoFromEd25519(kp.sk)

proc saveRouterCrypto*(path: string; crypto: RouterCrypto) =
  writeFile(path, "# Ed25519 key\nsecretKey=" & toHex(crypto.secretKey) & "\n")

proc loadOrCreateRouterCrypto*(path: string): RouterCrypto =
  if fileExists(path):
    for raw in readFile(path).splitLines():
      let line = raw.strip()
      if line.startsWith("secretKey="):
        let bytes = fromHex(line.split("=", 1)[1])
        if bytes.len != 64:
          raise newException(ValueError, "invalid Ed25519 secret key length")
        var sk: Ed25519SecretKey
        for i in 0 ..< 64: sk[i] = bytes[i]
        return routerCryptoFromEd25519(sk)
    raise newException(ValueError, "key file missing secretKey= line")
  result = newRouterCrypto()
  saveRouterCrypto(path, result)

proc bytesForSig*(node, parent: NodeId, seq, nonce, port: uint64): seq[byte] =
  for b in node.bytes: result.add b
  for b in parent.bytes: result.add b
  encodeUvarint(seq, result)
  encodeUvarint(nonce, result)
  encodeUvarint(port, result)

proc signSigRes*(crypto: RouterCrypto, node, parent: NodeId, seq, nonce, port: uint64): Signature64 =
  signDetached(crypto.secretKey, bytesForSig(node, parent, seq, nonce, port))

proc verifyRouterSig*(signer, node, parent: NodeId, seq, nonce, port: uint64, sig: Signature64): bool =
  verifyDetached(toEdPublic(signer), bytesForSig(node, parent, seq, nonce, port), sig)

proc check*(ann: RouterAnnounce): bool =
  if ann.port == 0 and ann.key != ann.parent: return false
  verifyRouterSig(ann.key, ann.key, ann.parent, ann.seq, ann.nonce, ann.port, ann.signature) and
    verifyRouterSig(ann.parent, ann.key, ann.parent, ann.seq, ann.nonce, ann.port, ann.parentSignature)

proc toWire*(ann: RouterAnnounce): Announce =
  Announce(key: ann.key, parent: ann.parent,
           sigRes: SigResFull(seq: ann.seq, nonce: ann.nonce, port: ann.port,
                              parentSignature: ann.parentSignature.toArr64()),
           signature: ann.signature.toArr64())

proc fromWireAnnounce*(ann: Announce): RouterAnnounce =
  RouterAnnounce(key: ann.key, parent: ann.parent, seq: ann.sigRes.seq,
                 nonce: ann.sigRes.nonce, port: ann.sigRes.port,
                 parentSignature: ann.sigRes.parentSignature.toSig64(),
                 signature: ann.signature.toSig64())

proc makeRootAnnounce*(crypto: RouterCrypto, seq, nonce: uint64): RouterAnnounce =
  let sig = crypto.signSigRes(crypto.publicKey, crypto.publicKey, seq, nonce, 0)
  RouterAnnounce(key: crypto.publicKey, parent: crypto.publicKey, seq: seq, nonce: nonce,
                 port: 0, parentSignature: sig, signature: sig)

proc makeChildAnnounce*(crypto: RouterCrypto, parent: NodeId, seq, nonce, port: uint64,
                        parentSignature: Signature64): RouterAnnounce =
  let sig = crypto.signSigRes(crypto.publicKey, parent, seq, nonce, port)
  RouterAnnounce(key: crypto.publicKey, parent: parent, seq: seq, nonce: nonce,
                 port: port, parentSignature: parentSignature, signature: sig)

proc pathInfoBytesForSig*(seq: uint64, path: Path): seq[byte] =
  encodeUvarint(seq, result)
  encodePath(path, result)

proc signPathInfo*(crypto: RouterCrypto, seq: uint64, path: Path): Signature64 =
  signDetached(crypto.secretKey, pathInfoBytesForSig(seq, path))

proc verifyPathInfo*(key: NodeId, seq: uint64, path: Path, sig: Signature64): bool =
  verifyDetached(toEdPublic(key), pathInfoBytesForSig(seq, path), sig)

# ---------------------------------------------------------------------------
# RTT tracking for SigReq/SigRes
# ---------------------------------------------------------------------------
# Revertron's Yggdrasil-ng postmortem describes a subtle bug: measuring RTT from
# peer-reader start instead of from each SigReq send time makes the apparent RTT
# grow with connection age and eventually poisons parent/path selection. Keep the
# send timestamp per peer and update it every time a SigReq is emitted.

import std/[tables, monotimes, times, options]

type
  PeerId* = uint64
  RttTracker* = object
    sentAt*: Table[PeerId, MonoTime]
    lastRttMs*: Table[PeerId, int64]

proc initRttTracker*(): RttTracker =
  RttTracker(sentAt: initTable[PeerId, MonoTime](), lastRttMs: initTable[PeerId, int64]())

proc markSigReqSent*(r: var RttTracker, peer: PeerId, now = getMonoTime()) =
  r.sentAt[peer] = now

proc handleSigResReceived*(r: var RttTracker, peer: PeerId, now = getMonoTime()): Option[int64] =
  if not r.sentAt.hasKey(peer): return none(int64)
  let ms = (now - r.sentAt[peer]).inMilliseconds
  r.lastRttMs[peer] = ms
  r.sentAt.del(peer)
  some(ms)

proc lastRtt*(r: RttTracker, peer: PeerId): Option[int64] =
  if r.lastRttMs.hasKey(peer): some(r.lastRttMs[peer]) else: none(int64)

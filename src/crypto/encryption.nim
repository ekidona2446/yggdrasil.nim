## End-to-end encryption and hybrid post-quantum API boundary.
##
## The default backend here is a deterministic development AEAD-like construction
## for tests and simulations. It authenticates frames with a 128-bit tag derived
## from `hash256` and XORs a hash stream. It is NOT cryptographically secure.
## Production must bind these APIs to Noise IK + X25519 + ML-KEM-1024/liboqs and
## ChaCha20-Poly1305/AES-GCM.

import std/[options]
import ../core/types
import ../core/identity
import ../util/bytes

type
  AeadAlgorithm* = enum aeadChaCha20Poly1305, aeadAes256Gcm, aeadDevOnly
  KemAlgorithm* = enum kemNone, kemMlKem1024, kemKyber1024

  CryptoConfig* = object
    postQuantum*: bool
    kem*: KemAlgorithm
    aead*: AeadAlgorithm
    perHopProtection*: bool

  Session* = object
    local*: NodeId
    remote*: NodeId
    key*: Bytes32
    sendNonce*: uint64
    recvNonceFloor*: uint64
    production*: bool

  EncryptedFrame* = object
    sender*: NodeId
    recipient*: NodeId
    nonce*: uint64
    ciphertext*: seq[byte]
    tag*: array[16, byte]

  HopFrame* = object
    nonce*: uint64
    payload*: seq[byte]
    tag*: array[16, byte]

proc defaultCryptoConfig*(): CryptoConfig =
  ## Safe-for-tests development profile. Production callers should pass an
  ## explicit ChaCha20-Poly1305/AES-GCM profile and require `production == true`.
  CryptoConfig(postQuantum: false, kem: kemNone,
               aead: aeadDevOnly, perHopProtection: false)

proc desiredProductionCryptoConfig*(): CryptoConfig =
  CryptoConfig(postQuantum: true, kem: kemMlKem1024,
               aead: aeadChaCha20Poly1305, perHopProtection: true)

proc productionCryptoAvailable*(): bool = false

proc pairwiseDevKey*(a, b: NodeId, domain = "yggdrasil-e2e-dev-key"): Bytes32 =
  ## Public-only deterministic key for tests. Not secure.
  var left = a
  var right = b
  if cmpNodeId(right, left) < 0:
    swap(left, right)
  hash256(concatBytes(left.bytes, right.bytes), domain)

proc initSession*(local: NodeIdentity, remote: NodeId,
                  cfg = defaultCryptoConfig()): Session =
  if cfg.aead != aeadDevOnly and not productionCryptoAvailable():
    raise newException(CatchableError, "production crypto backend is not linked")
  Session(local: local.publicKey, remote: remote,
          key: pairwiseDevKey(local.publicKey, remote), sendNonce: 0,
          recvNonceFloor: 0, production: false)

proc tag16(key: Bytes32, nonce: uint64, aad, ciphertext: openArray[byte]): array[16, byte] =
  let nb = u64le(nonce)
  let h = hash256(concatBytes(key, nb, aad, ciphertext), "yggdrasil-dev-aead-tag")
  for i in 0 ..< 16: result[i] = h[i]

proc xorStream(key: Bytes32, nonce: uint64, input: openArray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  var offset = 0
  var blockNo: uint64 = 0
  while offset < input.len:
    let nb = u64le(nonce)
    let bb = u64le(blockNo)
    let streamBlock = hash256(concatBytes(key, nb, bb), "yggdrasil-dev-stream")
    for j in 0 ..< min(32, input.len - offset):
      result[offset + j] = input[offset + j] xor streamBlock[j]
    offset += 32
    inc blockNo

proc seal*(s: var Session, plaintext: openArray[byte], aad: openArray[byte] = []): EncryptedFrame =
  inc s.sendNonce
  result.sender = s.local
  result.recipient = s.remote
  result.nonce = s.sendNonce
  result.ciphertext = xorStream(s.key, result.nonce, plaintext)
  result.tag = tag16(s.key, result.nonce, aad, result.ciphertext)

proc open*(s: var Session, frame: EncryptedFrame, aad: openArray[byte] = []): Option[seq[byte]] =
  if frame.recipient != s.local or frame.sender != s.remote: return none(seq[byte])
  if frame.nonce <= s.recvNonceFloor: return none(seq[byte])
  let expected = tag16(s.key, frame.nonce, aad, frame.ciphertext)
  if not constantTimeEq(expected, frame.tag): return none(seq[byte])
  s.recvNonceFloor = frame.nonce
  some(xorStream(s.key, frame.nonce, frame.ciphertext))

proc sealHop*(key: Bytes32, nonce: uint64, payload: openArray[byte]): HopFrame =
  result.nonce = nonce
  result.payload = xorStream(key, nonce, payload)
  result.tag = tag16(key, nonce, [], result.payload)

proc openHop*(key: Bytes32, frame: HopFrame): Option[seq[byte]] =
  let expected = tag16(key, frame.nonce, [], frame.payload)
  if not constantTimeEq(expected, frame.tag): return none(seq[byte])
  some(xorStream(key, frame.nonce, frame.payload))

proc hybridKemDescription*(cfg: CryptoConfig): string =
  if cfg.postQuantum:
    "X25519+" & $cfg.kem & " -> HKDF -> " & $cfg.aead
  else:
    "X25519 -> HKDF -> " & $cfg.aead

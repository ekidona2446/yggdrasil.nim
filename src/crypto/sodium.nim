## Minimal runtime-loaded libsodium bindings for Ironwood/Yggdrasil crypto.
##
## This avoids link-time dependency on libsodium while giving production-grade
## primitives when libsodium is installed. Required for real Ironwood sessions:
## Ed25519 signatures, Ed25519->Curve25519 conversion, Curve25519 keypairs, and
## XSalsa20-Poly1305 `crypto_box`.

import std/[dynlib]

type
  SodiumError* = object of CatchableError

  Ed25519PublicKey* = array[32, byte]
  Ed25519SecretKey* = array[64, byte]
  Curve25519PublicKey* = array[32, byte]
  Curve25519SecretKey* = array[32, byte]
  Nonce24* = array[24, byte]
  Signature64* = array[64, byte]

  SodiumApi* = ref object
    lib: LibHandle
    sodium_init: proc(): cint {.cdecl.}
    randombytes_buf: proc(buf: pointer, size: csize_t) {.cdecl.}
    crypto_sign_keypair: proc(pk, sk: pointer): cint {.cdecl.}
    crypto_sign_detached: proc(sig, siglen: pointer, msg: pointer, msglen: culonglong, sk: pointer): cint {.cdecl.}
    crypto_sign_verify_detached: proc(sig, msg: pointer, msglen: culonglong, pk: pointer): cint {.cdecl.}
    crypto_sign_ed25519_pk_to_curve25519: proc(curvePk, edPk: pointer): cint {.cdecl.}
    crypto_sign_ed25519_sk_to_curve25519: proc(curveSk, edSk: pointer): cint {.cdecl.}
    crypto_box_keypair: proc(pk, sk: pointer): cint {.cdecl.}
    crypto_box_easy: proc(ciph, msg: pointer, msglen: culonglong, nonce, pk, sk: pointer): cint {.cdecl.}
    crypto_box_open_easy: proc(msg, ciph: pointer, ciphen: culonglong, nonce, pk, sk: pointer): cint {.cdecl.}
    crypto_generichash: proc(outBuf: pointer, outLen: csize_t, inBuf: pointer, inLen: culonglong, key: pointer, keyLen: csize_t): cint {.cdecl.}

var cached*: SodiumApi

proc loadSym[T](lib: LibHandle, name: string): T =
  let p = symAddr(lib, name)
  if p == nil: raise newException(SodiumError, "libsodium missing symbol: " & name)
  cast[T](p)

proc loadSodium*(): SodiumApi =
  if cached != nil: return cached
  var lib: LibHandle
  for name in ["libsodium.so", "libsodium.so.23", "libsodium.dylib", "libsodium.dll"]:
    lib = loadLib(name)
    if lib != nil: break
  if lib == nil:
    raise newException(SodiumError, "libsodium not found (install libsodium23/libsodium-dev)")
  result = SodiumApi(lib: lib)
  result.sodium_init = loadSym[typeof(result.sodium_init)](lib, "sodium_init")
  result.randombytes_buf = loadSym[typeof(result.randombytes_buf)](lib, "randombytes_buf")
  result.crypto_sign_keypair = loadSym[typeof(result.crypto_sign_keypair)](lib, "crypto_sign_keypair")
  result.crypto_sign_detached = loadSym[typeof(result.crypto_sign_detached)](lib, "crypto_sign_detached")
  result.crypto_sign_verify_detached = loadSym[typeof(result.crypto_sign_verify_detached)](lib, "crypto_sign_verify_detached")
  result.crypto_sign_ed25519_pk_to_curve25519 = loadSym[typeof(result.crypto_sign_ed25519_pk_to_curve25519)](lib, "crypto_sign_ed25519_pk_to_curve25519")
  result.crypto_sign_ed25519_sk_to_curve25519 = loadSym[typeof(result.crypto_sign_ed25519_sk_to_curve25519)](lib, "crypto_sign_ed25519_sk_to_curve25519")
  result.crypto_box_keypair = loadSym[typeof(result.crypto_box_keypair)](lib, "crypto_box_keypair")
  result.crypto_box_easy = loadSym[typeof(result.crypto_box_easy)](lib, "crypto_box_easy")
  result.crypto_box_open_easy = loadSym[typeof(result.crypto_box_open_easy)](lib, "crypto_box_open_easy")
  result.crypto_generichash = loadSym[typeof(result.crypto_generichash)](lib, "crypto_generichash")
  if result.sodium_init() < 0:
    raise newException(SodiumError, "sodium_init failed")
  cached = result

proc available*(): bool =
  try:
    discard loadSodium()
    true
  except CatchableError:
    false

proc randomBytes*(n: int): seq[byte] =
  if n < 0: raise newException(ValueError, "negative size")
  let s = loadSodium()
  result = newSeq[byte](n)
  if n > 0: s.randombytes_buf(addr result[0], csize_t(n))

proc newEd25519Keypair*(): tuple[pk: Ed25519PublicKey, sk: Ed25519SecretKey] =
  let s = loadSodium()
  if s.crypto_sign_keypair(addr result.pk[0], addr result.sk[0]) != 0:
    raise newException(SodiumError, "crypto_sign_keypair failed")

proc signDetached*(sk: Ed25519SecretKey, msg: openArray[byte]): Signature64 =
  let s = loadSodium()
  var sigLen: culonglong
  let msgPtr = if msg.len == 0: nil else: unsafeAddr msg[0]
  if s.crypto_sign_detached(addr result[0], addr sigLen, msgPtr, culonglong(msg.len), unsafeAddr sk[0]) != 0:
    raise newException(SodiumError, "crypto_sign_detached failed")

proc verifyDetached*(pk: Ed25519PublicKey, msg: openArray[byte], sig: Signature64): bool =
  let s = loadSodium()
  let msgPtr = if msg.len == 0: nil else: unsafeAddr msg[0]
  s.crypto_sign_verify_detached(unsafeAddr sig[0], msgPtr, culonglong(msg.len), unsafeAddr pk[0]) == 0

proc edPublicToCurve25519*(pk: Ed25519PublicKey): Curve25519PublicKey =
  let s = loadSodium()
  if s.crypto_sign_ed25519_pk_to_curve25519(addr result[0], unsafeAddr pk[0]) != 0:
    raise newException(SodiumError, "ed25519 public key cannot convert to curve25519")

proc edSecretToCurve25519*(sk: Ed25519SecretKey): Curve25519SecretKey =
  let s = loadSodium()
  if s.crypto_sign_ed25519_sk_to_curve25519(addr result[0], unsafeAddr sk[0]) != 0:
    raise newException(SodiumError, "ed25519 secret key cannot convert to curve25519")

proc newCurve25519Keypair*(): tuple[pk: Curve25519PublicKey, sk: Curve25519SecretKey] =
  let s = loadSodium()
  if s.crypto_box_keypair(addr result.pk[0], addr result.sk[0]) != 0:
    raise newException(SodiumError, "crypto_box_keypair failed")

proc nonceForU64*(value: uint64): Nonce24 =
  ## 16 zero bytes + big-endian u64, matching Ironwood/Yggdrasil-ng.
  for i in 0 ..< 8:
    result[16 + i] = byte((value shr ((7 - i) * 8)) and 0xff'u64)

proc boxSeal*(msg: openArray[byte], nonce: Nonce24, theirPk: Curve25519PublicKey, ourSk: Curve25519SecretKey): seq[byte] =
  let s = loadSodium()
  result = newSeq[byte](msg.len + 16)
  let msgPtr = if msg.len == 0: nil else: unsafeAddr msg[0]
  if s.crypto_box_easy(addr result[0], msgPtr, culonglong(msg.len), unsafeAddr nonce[0], unsafeAddr theirPk[0], unsafeAddr ourSk[0]) != 0:
    raise newException(SodiumError, "crypto_box_easy failed")

proc boxOpen*(ciphertext: openArray[byte], nonce: Nonce24, theirPk: Curve25519PublicKey, ourSk: Curve25519SecretKey): seq[byte] =
  if ciphertext.len < 16: raise newException(SodiumError, "ciphertext too short")
  let s = loadSodium()
  result = newSeq[byte](ciphertext.len - 16)
  if s.crypto_box_open_easy(addr result[0], unsafeAddr ciphertext[0], culonglong(ciphertext.len), unsafeAddr nonce[0], unsafeAddr theirPk[0], unsafeAddr ourSk[0]) != 0:
    raise newException(SodiumError, "crypto_box_open_easy authentication failed")

proc blake2b512*(data: openArray[byte], key: openArray[byte] = []): array[64, byte] =
  let s = loadSodium()
  let dataPtr = if data.len == 0: nil else: unsafeAddr data[0]
  let keyPtr = if key.len == 0: nil else: unsafeAddr key[0]
  if s.crypto_generichash(addr result[0], csize_t(64), dataPtr, culonglong(data.len), keyPtr, csize_t(key.len)) != 0:
    raise newException(SodiumError, "crypto_generichash failed")

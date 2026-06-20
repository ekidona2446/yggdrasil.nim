## Monocypher backend for Yggdrasil.
##
## This binding provides the primitives required by Yggdrasil:
##   - X25519 key exchange (core of crypto_box)
##   - Ed25519 signatures (node identity & session authentication)
##   - Ed25519 <-> X25519 key conversion (required for unified keys)
##   - AEAD encryption (XChaCha20-Poly1305)
##
## Note: Yggdrasil's original implementation uses NaCl crypto_box
## (XSalsa20-Poly1305). Monocypher uses XChaCha20-Poly1305 instead.
## For full binary compatibility with existing Yggdrasil nodes you
## should still prefer libsodium. This backend is excellent for:
##   - New Nim implementations
##   - Environments where a smaller library is preferred
##   - When only X25519 + Ed25519 are needed

import std/dynlib

type
  MonocypherError* = object of CatchableError
  MonoKey32* = array[32, byte]
  MonoKey64* = array[64, byte]
  MonoMac16* = array[16, byte]
  MonoNonce24* = array[24, byte]

  MonocypherApi* = ref object
    lib: LibHandle
    crypto_x25519: proc(shared, secret, publicKey: pointer) {.cdecl.}
    crypto_x25519_public_key: proc(publicKey, secret: pointer) {.cdecl.}
    crypto_aead_lock: proc(cipher, mac, key, nonce, ad: pointer, adSize: csize_t,
                           plain: pointer, textSize: csize_t) {.cdecl.}
    crypto_aead_unlock: proc(plain, mac, key, nonce, ad: pointer, adSize: csize_t,
                             cipher: pointer, textSize: csize_t): cint {.cdecl.}
    crypto_ed25519_key_pair: proc(secretKey, publicKey, seed: pointer) {.cdecl.}
    crypto_ed25519_sign: proc(signature, secretKey, message: pointer, messageSize: csize_t) {.cdecl.}
    crypto_ed25519_check: proc(signature, publicKey, message: pointer, messageSize: csize_t): cint {.cdecl.}
    # Optional conversion helpers (present in recent Monocypher builds with Ed25519)
    crypto_from_ed25519_private: proc(x25519, ed25519: pointer) {.cdecl.}
    crypto_from_ed25519_public: proc(x25519, ed25519: pointer) {.cdecl.}

var cachedMono*: MonocypherApi

proc symOptional[T](lib: LibHandle, name: string): T =
  cast[T](symAddr(lib, name))

proc symRequired[T](lib: LibHandle, name: string): T =
  let p = symAddr(lib, name)
  if p == nil: raise newException(MonocypherError, "Monocypher missing symbol: " & name)
  cast[T](p)

proc loadMonocypher*(): MonocypherApi =
  if cachedMono != nil: return cachedMono
  var lib: LibHandle
  for name in ["libmonocypher.so", "libmonocypher.so.4", "libmonocypher.dylib", "monocypher.dll"]:
    lib = loadLib(name)
    if lib != nil: break
  if lib == nil: raise newException(MonocypherError, "Monocypher library not found")

  result = MonocypherApi(lib: lib)
  result.crypto_x25519 = symRequired[typeof(result.crypto_x25519)](lib, "crypto_x25519")
  result.crypto_x25519_public_key = symRequired[typeof(result.crypto_x25519_public_key)](lib, "crypto_x25519_public_key")
  result.crypto_aead_lock = symRequired[typeof(result.crypto_aead_lock)](lib, "crypto_aead_lock")
  result.crypto_aead_unlock = symRequired[typeof(result.crypto_aead_unlock)](lib, "crypto_aead_unlock")

  # Ed25519 is optional in some builds
  result.crypto_ed25519_key_pair = symOptional[typeof(result.crypto_ed25519_key_pair)](lib, "crypto_ed25519_key_pair")
  result.crypto_ed25519_sign = symOptional[typeof(result.crypto_ed25519_sign)](lib, "crypto_ed25519_sign")
  result.crypto_ed25519_check = symOptional[typeof(result.crypto_ed25519_check)](lib, "crypto_ed25519_check")

  # Conversion helpers (may be absent in older builds)
  result.crypto_from_ed25519_private = symOptional[typeof(result.crypto_from_ed25519_private)](lib, "crypto_from_ed25519_private")
  result.crypto_from_ed25519_public = symOptional[typeof(result.crypto_from_ed25519_public)](lib, "crypto_from_ed25519_public")

  cachedMono = result

proc available*(): bool =
  try:
    discard loadMonocypher()
    true
  except CatchableError:
    false

proc hasEd25519*(api = loadMonocypher()): bool =
  api.crypto_ed25519_key_pair != nil and
  api.crypto_ed25519_sign != nil and
  api.crypto_ed25519_check != nil

proc hasEdToX25519Conversion*(api = loadMonocypher()): bool =
  api.crypto_from_ed25519_private != nil and api.crypto_from_ed25519_public != nil

# ------------------------------------------------------------------
# X25519
# ------------------------------------------------------------------
proc x25519PublicKey*(secret: MonoKey32): MonoKey32 =
  let api = loadMonocypher()
  api.crypto_x25519_public_key(addr result[0], unsafeAddr secret[0])

proc x25519*(secret, publicKey: MonoKey32): MonoKey32 =
  let api = loadMonocypher()
  api.crypto_x25519(addr result[0], unsafeAddr secret[0], unsafeAddr publicKey[0])

# ------------------------------------------------------------------
# Ed25519
# ------------------------------------------------------------------
proc ed25519KeyPair*(seed: MonoKey32): tuple[secret: MonoKey64, public: MonoKey32] =
  let api = loadMonocypher()
  if not hasEd25519(api):
    raise newException(MonocypherError, "Monocypher was built without Ed25519 support")
  api.crypto_ed25519_key_pair(addr result.secret[0], addr result.public[0], unsafeAddr seed[0])

proc ed25519Sign*(secret: MonoKey64, message: openArray[byte]): array[64, byte] =
  let api = loadMonocypher()
  if not hasEd25519(api):
    raise newException(MonocypherError, "Monocypher was built without Ed25519 support")
  let msgPtr = if message.len == 0: nil else: unsafeAddr message[0]
  api.crypto_ed25519_sign(addr result[0], unsafeAddr secret[0], msgPtr, csize_t(message.len))

proc ed25519Verify*(public: MonoKey32, message: openArray[byte], signature: array[64, byte]): bool =
  let api = loadMonocypher()
  if not hasEd25519(api):
    raise newException(MonocypherError, "Monocypher was built without Ed25519 support")
  let msgPtr = if message.len == 0: nil else: unsafeAddr message[0]
  api.crypto_ed25519_check(unsafeAddr signature[0], unsafeAddr public[0], msgPtr, csize_t(message.len)) == 0

# ------------------------------------------------------------------
# Ed25519 <-> X25519 conversion (Yggdrasil requirement)
# ------------------------------------------------------------------
proc ed25519PrivateToX25519*(edSecret: MonoKey64): MonoKey32 =
  let api = loadMonocypher()
  if hasEdToX25519Conversion(api):
    api.crypto_from_ed25519_private(addr result[0], unsafeAddr edSecret[0])
  else:
    # Fallback: use the standard conversion algorithm (same as libsodium)
    # This is the hash-and-clamp method used by both libsodium and Monocypher
    var hash: array[64, byte]
    # In a real implementation we would call crypto_blake2b here.
    # For now we raise if the native helper is missing.
    raise newException(MonocypherError, "Monocypher build does not expose ed25519->x25519 conversion helpers")

proc ed25519PublicToX25519*(edPublic: MonoKey32): MonoKey32 =
  let api = loadMonocypher()
  if hasEdToX25519Conversion(api):
    api.crypto_from_ed25519_public(addr result[0], unsafeAddr edPublic[0])
  else:
    raise newException(MonocypherError, "Monocypher build does not expose ed25519->x25519 conversion helpers")

# ------------------------------------------------------------------
# AEAD (XChaCha20-Poly1305)
# ------------------------------------------------------------------
proc aeadLock*(key: MonoKey32, nonce: MonoNonce24, plain: openArray[byte],
               ad: openArray[byte] = []): tuple[cipher: seq[byte], mac: MonoMac16] =
  let api = loadMonocypher()
  result.cipher = newSeq[byte](plain.len)
  let plainPtr = if plain.len == 0: nil else: unsafeAddr plain[0]
  let adPtr = if ad.len == 0: nil else: unsafeAddr ad[0]
  let cipherPtr = if result.cipher.len == 0: nil else: addr result.cipher[0]
  api.crypto_aead_lock(cipherPtr, addr result.mac[0], unsafeAddr key[0], unsafeAddr nonce[0],
                       adPtr, csize_t(ad.len), plainPtr, csize_t(plain.len))

proc aeadUnlock*(key: MonoKey32, nonce: MonoNonce24, cipher: openArray[byte],
                 mac: MonoMac16, ad: openArray[byte] = []): seq[byte] =
  let api = loadMonocypher()
  result = newSeq[byte](cipher.len)
  let cPtr = if cipher.len == 0: nil else: unsafeAddr cipher[0]
  let adPtr = if ad.len == 0: nil else: unsafeAddr ad[0]
  let plainPtr = if result.len == 0: nil else: addr result[0]
  if api.crypto_aead_unlock(plainPtr, unsafeAddr mac[0], unsafeAddr key[0], unsafeAddr nonce[0],
                            adPtr, csize_t(ad.len), cPtr, csize_t(cipher.len)) != 0:
    raise newException(MonocypherError, "Monocypher AEAD authentication failed")

# XSalsa20-Poly1305 is implemented in xsalsa20.nim
import xsalsa20
export xsalsa20
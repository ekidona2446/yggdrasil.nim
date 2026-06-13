## Optional runtime-loaded Monocypher backend.
##
## Monocypher is useful as a compact fallback for *some* primitives:
## X25519, Ed25519 (when built with the optional Ed25519/SHA-512 module), and
## XChaCha20-Poly1305 AEAD. It is not a drop-in replacement for libsodium's
## `crypto_box_easy`, because public Yggdrasil/Ironwood uses NaCl-compatible
## XSalsa20-Poly1305 boxes. This module is therefore a capability probe and
## partial backend, not wired into Ironwood sessions by default.

import std/dynlib

type
  MonocypherError* = object of CatchableError
  MonoKey32* = array[32, byte]
  MonoKey64* = array[64, byte]
  MonoMac16* = array[16, byte]

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

var cachedMono*: MonocypherApi

proc symOptional[T](lib: LibHandle, name: string): T = cast[T](symAddr(lib, name))
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
  ## Ed25519 is optional in Monocypher builds. If absent, callers can still use
  ## X25519/XChaCha functionality, but cannot replace Yggdrasil metadata/router
  ## signatures.
  result.crypto_ed25519_key_pair = symOptional[typeof(result.crypto_ed25519_key_pair)](lib, "crypto_ed25519_key_pair")
  result.crypto_ed25519_sign = symOptional[typeof(result.crypto_ed25519_sign)](lib, "crypto_ed25519_sign")
  result.crypto_ed25519_check = symOptional[typeof(result.crypto_ed25519_check)](lib, "crypto_ed25519_check")
  cachedMono = result

proc available*(): bool =
  try:
    discard loadMonocypher()
    true
  except CatchableError:
    false

proc hasEd25519*(api = loadMonocypher()): bool =
  api.crypto_ed25519_key_pair != nil and api.crypto_ed25519_sign != nil and api.crypto_ed25519_check != nil

proc x25519PublicKey*(secret: MonoKey32): MonoKey32 =
  let api = loadMonocypher()
  api.crypto_x25519_public_key(addr result[0], unsafeAddr secret[0])

proc x25519*(secret, publicKey: MonoKey32): MonoKey32 =
  let api = loadMonocypher()
  api.crypto_x25519(addr result[0], unsafeAddr secret[0], unsafeAddr publicKey[0])

proc aeadLock*(key, nonce: MonoKey32, plain: openArray[byte], ad: openArray[byte] = []): tuple[cipher: seq[byte], mac: MonoMac16] =
  ## Monocypher AEAD is XChaCha20-Poly1305 with a 24-byte nonce. The `nonce`
  ## parameter uses the first 24 bytes of `MonoKey32` for ergonomic fixed-size use.
  let api = loadMonocypher()
  result.cipher = newSeq[byte](plain.len)
  let plainPtr = if plain.len == 0: nil else: unsafeAddr plain[0]
  let adPtr = if ad.len == 0: nil else: unsafeAddr ad[0]
  let cipherPtr = if result.cipher.len == 0: nil else: addr result.cipher[0]
  api.crypto_aead_lock(cipherPtr, addr result.mac[0], unsafeAddr key[0], unsafeAddr nonce[0],
                       adPtr, csize_t(ad.len), plainPtr, csize_t(plain.len))

proc aeadUnlock*(key, nonce: MonoKey32, cipher: openArray[byte], mac: MonoMac16, ad: openArray[byte] = []): seq[byte] =
  let api = loadMonocypher()
  result = newSeq[byte](cipher.len)
  let cPtr = if cipher.len == 0: nil else: unsafeAddr cipher[0]
  let adPtr = if ad.len == 0: nil else: unsafeAddr ad[0]
  let plainPtr = if result.len == 0: nil else: addr result[0]
  if api.crypto_aead_unlock(plainPtr, unsafeAddr mac[0], unsafeAddr key[0], unsafeAddr nonce[0],
                            adPtr, csize_t(ad.len), cPtr, csize_t(cipher.len)) != 0:
    raise newException(MonocypherError, "Monocypher AEAD authentication failed")

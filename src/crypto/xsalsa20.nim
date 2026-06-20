## XSalsa20 + Poly1305 implementation for crypto_box compatibility
## Pure Nim implementation (no external dependencies except Poly1305 from Monocypher)

import monocypher

proc rotl(x: uint32, n: int): uint32 {.inline.} =
  (x shl n) or (x shr (32 - n))

proc quarterRound(a, b, c, d: var uint32) =
  a += b; d = rotl(d xor a, 16)
  c += d; b = rotl(b xor c, 12)
  a += b; d = rotl(d xor a, 8)
  c += d; b = rotl(b xor c, 7)

proc salsa20Block(output: var array[64, byte]; key: array[32, byte];
                  nonce: array[8, byte]; counter: uint64) =
  var x: array[16, uint32]
  x[0]  = 0x61707865'u32
  x[5]  = 0x3320646e'u32
  x[10] = 0x79622d32'u32
  x[15] = 0x6b206574'u32

  for i in 0..<8:
    x[1+i] = cast[ptr uint32](unsafeAddr key[i*4])[]
  x[6] = cast[ptr uint32](unsafeAddr nonce[0])[]
  x[7] = cast[ptr uint32](unsafeAddr nonce[4])[]
  x[8] = uint32(counter)
  x[9] = uint32(counter shr 32)

  var y = x
  for _ in 0..<10:
    quarterRound(y[0], y[4], y[8], y[12])
    quarterRound(y[1], y[5], y[9], y[13])
    quarterRound(y[2], y[6], y[10], y[14])
    quarterRound(y[3], y[7], y[11], y[15])
    quarterRound(y[0], y[5], y[10], y[15])
    quarterRound(y[1], y[6], y[11], y[12])
    quarterRound(y[2], y[7], y[8], y[13])
    quarterRound(y[3], y[4], y[9], y[14])

  for i in 0..<16:
    let v = y[i] + x[i]
    copyMem(addr output[i*4], addr v, 4)

proc xsalsa20H*(subkey: var array[32, byte]; key: array[32, byte]; nonce16: array[16, byte]) =
  var sblock: array[64, byte]
  var n8: array[8, byte]
  copyMem(addr n8[0], unsafeAddr nonce16[0], 8)
  salsa20Block(sblock, key, n8, 0)
  copyMem(addr subkey[0], addr sblock[0], 32)

proc xsalsa20*(output: var openArray[byte]; key: array[32, byte];
               nonce: array[24, byte]; counter: uint64) =
  var subkey: array[32, byte]
  var nonce16: array[16, byte]
  copyMem(addr nonce16[0], unsafeAddr nonce[0], 16)
  xsalsa20H(subkey, key, nonce16)

  var n8: array[8, byte]
  copyMem(addr n8[0], unsafeAddr nonce[16], 8)

  var c = counter
  var pos = 0
  while pos < output.len:
    var sblock: array[64, byte]
    salsa20Block(sblock, subkey, n8, c)
    let take = min(64, output.len - pos)
    copyMem(addr output[pos], addr sblock[0], take)
    inc c
    inc pos, take

# ------------------------------------------------------------------
# crypto_box compatible API (XSalsa20-Poly1305)
# ------------------------------------------------------------------
const
  boxOverhead* = 16
  boxNonceSize* = 24

proc boxBeforenm*(k: var array[32, byte]; pk, sk: MonoKey32) =
  k = x25519(sk, pk)

# Poly1305 binding from Monocypher
# Windows? MacOS?
proc crypto_poly1305*(mac, key, msg: pointer; msgSize: csize_t) {.importc, dynlib: "libmonocypher.so.4".}

proc boxSealAfterPrecomputation*(c: var openArray[byte]; m: openArray[byte];
                                 n: array[24, byte]; k: array[32, byte]) =
  var polyKey: array[32, byte]
  xsalsa20(polyKey, k, n, 0)

  # Encrypt (counter starts at 1)
  if m.len > 0:
    xsalsa20(c.toOpenArray(boxOverhead, boxOverhead + m.len - 1), k, n, 1)
    copyMem(addr c[boxOverhead], unsafeAddr m[0], m.len)

  # Compute Poly1305 tag over ciphertext
  var mac: array[16, byte]
  crypto_poly1305(addr mac[0], addr polyKey[0],
                  if m.len > 0: addr c[boxOverhead] else: nil,
                  csize_t(m.len))

  # Prepend MAC
  copyMem(addr c[0], addr mac[0], boxOverhead)

proc boxOpenAfterPrecomputation*(m: var openArray[byte]; c: openArray[byte];
                                 n: array[24, byte]; k: array[32, byte]): bool =
  if c.len < boxOverhead: return false

  var polyKey: array[32, byte]
  xsalsa20(polyKey, k, n, 0)

  let ctLen = c.len - boxOverhead
  var mac: array[16, byte]
  crypto_poly1305(addr mac[0], addr polyKey[0],
                  if ctLen > 0: unsafeAddr c[boxOverhead] else: nil,
                  csize_t(ctLen))

  # Verify MAC
  var expected: array[16, byte]
  copyMem(addr expected[0], unsafeAddr c[0], 16)
  if not equalMem(addr mac[0], addr expected[0], 16):
    return false

  # Decrypt
  if ctLen > 0:
    xsalsa20(m.toOpenArray(0, ctLen-1), k, n, 1)
    copyMem(addr m[0], unsafeAddr c[boxOverhead], ctLen)

  true

proc boxSeal*(c: var openArray[byte]; m: openArray[byte]; n: array[24, byte];
              pk, sk: MonoKey32) =
  var k: array[32, byte]
  boxBeforenm(k, pk, sk)
  boxSealAfterPrecomputation(c, m, n, k)

proc boxOpen*(m: var openArray[byte]; c: openArray[byte]; n: array[24, byte];
              pk, sk: MonoKey32): bool =
  var k: array[32, byte]
  boxBeforenm(k, pk, sk)
  boxOpenAfterPrecomputation(m, c, n, k)
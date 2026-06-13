## Utility byte routines used by deterministic core code.
##
## The `hash256` routine is intentionally small and dependency-free so tests can
## run without native crypto. It is NOT a cryptographic hash. Production builds
## must replace identity/session hashing with SHA-512/256 or a stronger KDF in
## the crypto backend.

import std/strutils
when not defined(posix):
  import std/times

export strutils.toLowerAscii

type
  Bytes32* = array[32, byte]
  Bytes16* = array[16, byte]

const HexDigits* = "0123456789abcdef"

proc toHex*(data: openArray[byte]): string =
  result = newString(data.len * 2)
  for i, b in data:
    result[i * 2] = HexDigits[int((b shr 4) and 0x0f)]
    result[i * 2 + 1] = HexDigits[int(b and 0x0f)]

proc fromHex*(s: string): seq[byte] =
  let clean = s.strip().toLowerAscii()
  if clean.len mod 2 != 0:
    raise newException(ValueError, "hex string must have even length")
  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    let a = clean[i * 2]
    let b = clean[i * 2 + 1]
    proc val(c: char): int =
      if c >= '0' and c <= '9': ord(c) - ord('0')
      elif c >= 'a' and c <= 'f': 10 + ord(c) - ord('a')
      else: raise newException(ValueError, "invalid hex character: " & $c)
    result[i] = byte((val(a) shl 4) or val(b))

proc bytes32FromHex*(s: string): Bytes32 =
  let raw = fromHex(s)
  if raw.len != 32:
    raise newException(ValueError, "expected 32-byte hex value")
  for i in 0 ..< 32: result[i] = raw[i]

proc appendBytes(result: var seq[byte], p: openArray[byte]) =
  for b in p: result.add b

proc concatBytes*(a: openArray[byte]): seq[byte] =
  result = newSeqOfCap[byte](a.len)
  result.appendBytes(a)

proc concatBytes*(a, b: openArray[byte]): seq[byte] =
  result = newSeqOfCap[byte](a.len + b.len)
  result.appendBytes(a)
  result.appendBytes(b)

proc concatBytes*(a, b, c: openArray[byte]): seq[byte] =
  result = newSeqOfCap[byte](a.len + b.len + c.len)
  result.appendBytes(a)
  result.appendBytes(b)
  result.appendBytes(c)

proc concatBytes*(a, b, c, d: openArray[byte]): seq[byte] =
  result = newSeqOfCap[byte](a.len + b.len + c.len + d.len)
  result.appendBytes(a)
  result.appendBytes(b)
  result.appendBytes(c)
  result.appendBytes(d)

proc u64le*(x: uint64): array[8, byte] =
  for i in 0 ..< 8:
    result[i] = byte((x shr (i * 8)) and 0xff'u64)

proc readU64be*(data: openArray[byte], offset: int): uint64 =
  if offset + 8 > data.len: raise newException(ValueError, "short buffer")
  for i in 0 ..< 8:
    result = (result shl 8) or uint64(data[offset + i])

proc mix64(x0: uint64): uint64 =
  ## SplitMix64 avalanche used by `hash256`.
  var x = x0
  x = (x xor (x shr 30)) * 0xbf58476d1ce4e5b9'u64
  x = (x xor (x shr 27)) * 0x94d049bb133111eb'u64
  result = x xor (x shr 31)

proc hash64*(data: openArray[byte], seed = 0x9e3779b97f4a7c15'u64): uint64 =
  ## Deterministic non-cryptographic hash for maps/simulations.
  var h = seed xor uint64(data.len)
  var i = 0
  while i + 8 <= data.len:
    var w: uint64
    for j in 0 ..< 8:
      w = w or (uint64(data[i + j]) shl (j * 8))
    h = mix64(h xor w)
    i += 8
  var tail: uint64
  var shift = 0
  while i < data.len:
    tail = tail or (uint64(data[i]) shl shift)
    shift += 8
    inc i
  result = mix64(h xor tail)

proc stringBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(ord(c) and 0xff)

proc hash256*(data: openArray[byte], domain = "yggdrasil-dev-hash"): Bytes32 =
  ## Four independent SplitMix64 lanes. Development/testing only.
  let dbytes = stringBytes(domain)
  let base = hash64(dbytes, 0x243f6a8885a308d3'u64) xor hash64(data)
  for lane in 0 ..< 4:
    let laneVal = mix64(base xor uint64(lane) * 0x9e3779b97f4a7c15'u64 xor
                        hash64(data, 0xa4093822299f31d0'u64 + uint64(lane)))
    let le = u64le(laneVal)
    for j in 0 ..< 8:
      result[lane * 8 + j] = le[j]

proc constantTimeEq*(a, b: openArray[byte]): bool =
  if a.len != b.len: return false
  var acc: byte = 0
  for i in 0 ..< a.len:
    acc = acc or (a[i] xor b[i])
  result = acc == 0

proc secureRandomBytes*(n: int): seq[byte] =
  ## Best-effort secure random bytes. POSIX uses /dev/urandom. The Windows branch
  ## is a deterministic fallback placeholder for tests; production Windows must
  ## use BCryptGenRandom/RtlGenRandom.
  if n < 0: raise newException(ValueError, "negative byte count")
  result = newSeq[byte](n)
  when defined(posix):
    if n == 0: return
    var f = open("/dev/urandom", fmRead)
    defer: f.close()
    let got = f.readBuffer(addr result[0], n)
    if got != n:
      raise newException(IOError, "short read from /dev/urandom")
  else:
    var x = uint64(epochTime() * 1000000) xor 0x6a09e667f3bcc909'u64
    for i in 0 ..< n:
      x = mix64(x + uint64(i))
      result[i] = byte(x and 0xff)

proc wipe*(data: var openArray[byte]) =
  for i in 0 ..< data.len: data[i] = 0

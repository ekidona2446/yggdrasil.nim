## Ironwood/Yggdrasil bloom filter.
##
## Compatible with Go bits-and-blooms/bloom as used by yggdrasil-go and
## Yggdrasil-ng: Murmur3 x64 128-bit base hashes, 8192 bits, k=8, and the
## double-hashing location formula used by the Go library.

import std/[tables, options]
import ../core/types
import ./wire

const
  BloomBits* = 8192
  BloomK* = 8
  BloomU64s* = BloomBits div 64

type
  BloomFilter* = object
    bits*: array[BloomU64s, uint64]

  BloomInfo* = object
    send*: BloomFilter
    recv*: BloomFilter
    seq*: uint16
    onTree*: bool
    zDirty*: bool

  Blooms* = object
    infos*: Table[NodeId, BloomInfo]

proc rotl64(x: uint64, r: int): uint64 = (x shl r) or (x shr (64 - r))

proc fmix64(k0: uint64): uint64 =
  var k = k0
  k = k xor (k shr 33)
  k = k * 0xff51afd7ed558ccd'u64
  k = k xor (k shr 33)
  k = k * 0xc4ceb9fe1a85ec53'u64
  k = k xor (k shr 33)
  k

proc getBlock64le(data: openArray[byte], off: int): uint64 =
  for i in 0 ..< 8:
    result = result or (uint64(data[off + i]) shl (8 * i))

proc murmur3x64_128*(data: openArray[byte], seed = 0'u32): tuple[h1, h2: uint64] =
  const c1 = 0x87c37b91114253d5'u64
  const c2 = 0x4cf5ad432745937f'u64
  var h1 = uint64(seed)
  var h2 = uint64(seed)
  let nblocks = data.len div 16
  for bi in 0 ..< nblocks:
    var k1 = getBlock64le(data, bi * 16)
    var k2 = getBlock64le(data, bi * 16 + 8)

    k1 *= c1; k1 = rotl64(k1, 31); k1 *= c2; h1 = h1 xor k1
    h1 = rotl64(h1, 27); h1 += h2; h1 = h1 * 5'u64 + 0x52dce729'u64

    k2 *= c2; k2 = rotl64(k2, 33); k2 *= c1; h2 = h2 xor k2
    h2 = rotl64(h2, 31); h2 += h1; h2 = h2 * 5'u64 + 0x38495ab5'u64

  var k1, k2: uint64
  let tail = nblocks * 16
  let rem = data.len and 15
  if rem >= 15: k2 = k2 xor (uint64(data[tail + 14]) shl 48)
  if rem >= 14: k2 = k2 xor (uint64(data[tail + 13]) shl 40)
  if rem >= 13: k2 = k2 xor (uint64(data[tail + 12]) shl 32)
  if rem >= 12: k2 = k2 xor (uint64(data[tail + 11]) shl 24)
  if rem >= 11: k2 = k2 xor (uint64(data[tail + 10]) shl 16)
  if rem >= 10: k2 = k2 xor (uint64(data[tail + 9]) shl 8)
  if rem >= 9:
    k2 = k2 xor uint64(data[tail + 8])
    k2 *= c2; k2 = rotl64(k2, 33); k2 *= c1; h2 = h2 xor k2
  if rem >= 8: k1 = k1 xor (uint64(data[tail + 7]) shl 56)
  if rem >= 7: k1 = k1 xor (uint64(data[tail + 6]) shl 48)
  if rem >= 6: k1 = k1 xor (uint64(data[tail + 5]) shl 40)
  if rem >= 5: k1 = k1 xor (uint64(data[tail + 4]) shl 32)
  if rem >= 4: k1 = k1 xor (uint64(data[tail + 3]) shl 24)
  if rem >= 3: k1 = k1 xor (uint64(data[tail + 2]) shl 16)
  if rem >= 2: k1 = k1 xor (uint64(data[tail + 1]) shl 8)
  if rem >= 1:
    k1 = k1 xor uint64(data[tail])
    k1 *= c1; k1 = rotl64(k1, 31); k1 *= c2; h1 = h1 xor k1

  h1 = h1 xor uint64(data.len)
  h2 = h2 xor uint64(data.len)
  h1 += h2
  h2 += h1
  h1 = fmix64(h1)
  h2 = fmix64(h2)
  h1 += h2
  h2 += h1
  (h1, h2)

proc baseHashes(data: openArray[byte]): array[4, uint64] =
  let a = murmur3x64_128(data, 0)
  var withOne = newSeqOfCap[byte](data.len + 1)
  for b in data: withOne.add b
  withOne.add 1'u8
  let b = murmur3x64_128(withOne, 0)
  [a.h1, a.h2, b.h1, b.h2]

proc location(h: array[4, uint64], i, m: int): int =
  let ii = uint64(i)
  let base = h[i mod 2]
  let inner = (i + (i mod 2)) mod 4
  let hashIdx = 2 + (inner div 2)
  let loc = base + (ii * h[hashIdx])
  int(loc mod uint64(m))

proc setBit*(bf: var BloomFilter, bit: int) =
  bf.bits[bit div 64] = bf.bits[bit div 64] or (1'u64 shl (bit mod 64))

proc getBit*(bf: BloomFilter, bit: int): bool =
  ((bf.bits[bit div 64] shr (bit mod 64)) and 1'u64) == 1'u64

proc add*(bf: var BloomFilter, key: openArray[byte]) =
  let h = baseHashes(key)
  for i in 0 ..< BloomK: bf.setBit(location(h, i, BloomBits))

proc add*(bf: var BloomFilter, key: NodeId) = bf.add(bloomTransform(key).bytes)

proc test*(bf: BloomFilter, key: openArray[byte]): bool =
  let h = baseHashes(key)
  for i in 0 ..< BloomK:
    if not bf.getBit(location(h, i, BloomBits)): return false
  true

proc test*(bf: BloomFilter, key: NodeId): bool = bf.test(bloomTransform(key).bytes)

proc merge*(bf: var BloomFilter, other: BloomFilter) =
  for i in 0 ..< BloomU64s: bf.bits[i] = bf.bits[i] or other.bits[i]

proc popcount64(x0: uint64): int =
  var x = x0
  while x != 0:
    x = x and (x - 1)
    inc result

proc countOnes*(bf: BloomFilter): int =
  for u in bf.bits: result += popcount64(u)

proc toWireRaw*(bf: BloomFilter): array[BloomU64s, uint64] = bf.bits
proc fromWireRaw*(bits: array[BloomU64s, uint64]): BloomFilter = BloomFilter(bits: bits)

proc encode*(bf: BloomFilter): seq[byte] = encodeBloom(bf.bits)

proc decodeBloomFilter*(payload: openArray[byte]): Option[BloomFilter] =
  let raw = decodeBloom(payload)
  if raw.isNone: none(BloomFilter) else: some(BloomFilter(bits: raw.get()))

proc initBlooms*(): Blooms = Blooms(infos: initTable[NodeId, BloomInfo]())

proc addPeer*(b: var Blooms, key: NodeId) =
  if not b.infos.hasKey(key): b.infos[key] = BloomInfo()

proc removePeer*(b: var Blooms, key: NodeId) =
  if b.infos.hasKey(key): b.infos.del(key)

proc handleBloom*(b: var Blooms, peer: NodeId, filter: BloomFilter) =
  b.addPeer(peer)
  b.infos[peer].recv = filter

proc setOnTree*(b: var Blooms, peer: NodeId, onTree: bool) =
  b.addPeer(peer)
  b.infos[peer].onTree = onTree

proc getBloomFor*(b: var Blooms, peer, ourKey: NodeId, keepOnes = true): BloomFilter =
  var bf = BloomFilter()
  bf.add(ourKey)
  for k, info in b.infos:
    if info.onTree and k != peer:
      bf.merge(info.recv)
  b.addPeer(peer)
  if keepOnes: bf.merge(b.infos[peer].send)
  b.infos[peer].send = bf
  bf

proc getMulticastTargets*(b: Blooms, fromKey, toKey: NodeId): seq[NodeId] =
  for k, info in b.infos:
    if info.onTree and k != fromKey and info.recv.test(toKey): result.add k

proc countTargets*(b: Blooms, xformedKey: NodeId): int =
  for _, info in b.infos:
    if info.onTree and info.recv.test(xformedKey): inc result

proc fixOnTree*(b: var Blooms, selfKey, selfParent: NodeId, parentMap: Table[NodeId, NodeId]): seq[tuple[peer: NodeId, filter: BloomFilter]] =
  ## Update on-tree status based on current tree state. Parent and children of
  ## this node are on-tree; peers that drop off-tree get a blank filter.
  for peer, info0 in b.infos.mpairs:
    let was = info0.onTree
    var now = false
    if peer == selfParent: now = true
    elif parentMap.hasKey(peer) and parentMap[peer] == selfKey: now = true
    info0.onTree = now
    if was and not now:
      info0.send = BloomFilter()
      result.add (peer, info0.send)

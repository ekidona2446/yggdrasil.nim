import std/[unittest, options]
import ../src/ironwood/bloom
import ../src/util/bytes as ubytes
import ../src/core/types

suite "ironwood bloom":
  test "known value for key [42;32] matches Yggdrasil-ng":
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 42
    var bf = BloomFilter()
    bf.add(key)
    let expectedHex = "fdbfffbfff7ffe7ffffffffcffffffff0000000000000000000000000000000020000000000000000000000000080000200000000000000000000000000080000000200000000000020000000000000000020000000000000200000000000000"
    check ubytes.toHex(bf.encode()) == expectedHex
    let decoded = decodeBloomFilter(ubytes.fromHex(expectedHex))
    check decoded.isSome
    check decoded.get().test(key)
    check decoded.get().bits == bf.bits

  test "merge and multicast targets":
    var a, b: NodeId
    a.bytes[31] = 1
    b.bytes[31] = 2
    var recv = BloomFilter()
    recv.add(b)
    var blooms = initBlooms()
    blooms.addPeer(a)
    blooms.handleBloom(a, recv)
    blooms.setOnTree(a, true)
    let targets = blooms.getMulticastTargets(NodeId(), b)
    check targets.len == 1
    check targets[0] == a

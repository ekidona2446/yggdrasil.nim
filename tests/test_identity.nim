import std/[unittest, os]
import ../src/core/identity
import ../src/core/types
import ../src/util/bytes

suite "identity":
  test "deterministic key and Yggdrasil address derivation":
    var seed: Bytes32
    for i in 0 ..< 32: seed[i] = byte(i)
    let a = identityFromSeed(seed)
    let b = identityFromSeed(seed)
    check a.publicKey == b.publicKey
    check a.ipv6 == b.ipv6
    check a.ipv6[0] == 0x02'u8

  test "save and load key file":
    var seed: Bytes32
    for i in 0 ..< 32: seed[i] = byte(255 - i)
    let id = identityFromSeed(seed)
    let path = getTempDir() / "ydrasil-test.key"
    id.save(path)
    let loaded = loadIdentity(path)
    check loaded.publicKey == id.publicKey
    check loaded.privateSeed == id.privateSeed
    removeFile(path)

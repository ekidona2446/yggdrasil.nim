import std/[unittest, options]
import ../src/core/[identity, types]
import ../src/crypto/encryption
import ../src/util/bytes

proc makeId(n: byte): NodeIdentity =
  var seed: Bytes32
  for i in 0 ..< 32: seed[i] = n
  identityFromSeed(seed)

suite "crypto development backend":
  test "sealed frames authenticate and decrypt between peers":
    let a = makeId(1)
    let b = makeId(2)
    var sa = initSession(a, b.publicKey)
    var sb = initSession(b, a.publicKey)
    var frame = sa.seal(@[byte(1), byte(2), byte(3)], @[byte(9)])
    let opened = sb.open(frame, @[byte(9)])
    check opened.isSome
    check opened.get() == @[byte(1), byte(2), byte(3)]
    frame.ciphertext[0] = frame.ciphertext[0] xor 1
    check sb.open(frame, @[byte(9)]).isNone

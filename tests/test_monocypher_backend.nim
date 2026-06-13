import std/unittest
import ../src/crypto/monocypher

suite "monocypher optional backend":
  test "runtime capability probe does not crash":
    discard available()
    check true

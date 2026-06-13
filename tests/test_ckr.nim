import std/[unittest, options]
import ../src/core/[identity, ckr, types]
import ../src/util/bytes

proc node(n: byte): NodeId =
  var seed: Bytes32
  for i in 0 ..< 32: seed[i] = n
  identityFromSeed(seed).publicKey

suite "CKR":
  test "route lookup and source validation":
    var table = initCkrTable()
    let remote = node(9)
    let r = parseCkrRoute("office", remote, ["10.42.0.0/16", "fd00:abcd::/48"],
                          ["10.10.0.0/16", "fd00:beef::/48"])
    table.addRoute(r)
    let hit = table.lookupRoute("10.42.1.2")
    check hit.isSome
    check hit.get().id == "office"
    check hit.get().validateIngress("10.10.1.1")
    check not hit.get().validateIngress("10.99.1.1")
    check table.lookupRoute("fd00:abcd::1").isSome

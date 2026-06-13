import std/[unittest, tables]
import ../src/core/[identity, tree, types]
import ../src/util/bytes

proc ident(n: byte): NodeId =
  var seed: Bytes32
  for i in 0 ..< 32: seed[i] = byte((int(n) + i) and 0xff)
  identityFromSeed(seed).publicKey

proc sync(a, b: var TreeState) =
  let ua = a.makeUpdate()
  let ub = b.makeUpdate()
  discard a.applyUpdate(b.selfId, ub)
  discard b.applyUpdate(a.selfId, ua)

suite "tree greedy routing":
  test "line topology converges and routes without loops":
    var ta = initTree(ident(1))
    var tb = initTree(ident(2))
    var tc = initTree(ident(3))
    for _ in 0 ..< 8:
      sync(ta, tb)
      sync(tb, tc)
    var nodes = initTable[NodeId, TreeState]()
    nodes[ta.selfId] = ta
    nodes[tb.selfId] = tb
    nodes[tc.selfId] = tc
    let path = routePath(nodes, ta.selfId, tc.selfId, tc.selfCoords)
    check validateLoopFree(path)
    check path.len >= 2
    check path[^1] == tc.selfId

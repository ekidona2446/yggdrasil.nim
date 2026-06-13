## Self-healing/routing convergence simulation.

import std/[tables, sequtils, strformat]
import ../src/core/[identity, tree, types]
import ../src/util/bytes

proc ident(n: int): NodeId =
  var seed: Bytes32
  for i in 0 ..< 32: seed[i] = byte((n * 17 + i) and 0xff)
  identityFromSeed(seed).publicKey

proc exchange(nodes: var Table[NodeId, TreeState], a, b: NodeId) =
  let ua = nodes[a].makeUpdate()
  let ub = nodes[b].makeUpdate()
  var ta = nodes[a]
  var tb = nodes[b]
  discard ta.applyUpdate(b, ub)
  discard tb.applyUpdate(a, ua)
  nodes[a] = ta
  nodes[b] = tb

proc converge(nodes: var Table[NodeId, TreeState], edges: seq[(NodeId, NodeId)], rounds = 10) =
  for _ in 0 ..< rounds:
    for e in edges: exchange(nodes, e[0], e[1])

when isMainModule:
  var ids: seq[NodeId]
  var nodes = initTable[NodeId, TreeState]()
  for i in 0 ..< 8:
    let id = ident(i)
    ids.add id
    nodes[id] = initTree(id)

  # A mesh with redundant links: ring plus two chords.
  var edges: seq[(NodeId, NodeId)]
  for i in 0 ..< ids.len:
    edges.add (ids[i], ids[(i + 1) mod ids.len])
  edges.add (ids[0], ids[4])
  edges.add (ids[2], ids[6])

  converge(nodes, edges, 12)
  let src = ids[1]
  let dst = ids[6]
  let before = routePath(nodes, src, dst, nodes[dst].selfCoords)
  echo &"before failure hops={before.len} loopFree={validateLoopFree(before)} delivered={before[^1] == dst}"

  # Simulate link failure on an active/ring edge and scoped LS update.
  let failed = edges[1]
  var a = nodes[failed[0]]
  var b = nodes[failed[1]]
  a.markNeighborDown(failed[1])
  b.markNeighborDown(failed[0])
  discard a.recomputeCoordinates()
  discard b.recomputeCoordinates()
  nodes[failed[0]] = a
  nodes[failed[1]] = b
  edges = edges.filterIt(it != failed and (it[1], it[0]) != failed)

  converge(nodes, edges, 12)
  let after = routePath(nodes, src, dst, nodes[dst].selfCoords)
  echo &"after failure hops={after.len} loopFree={validateLoopFree(after)} delivered={after[^1] == dst}"
  if not validateLoopFree(after) or after[^1] != dst:
    quit "simulation failed", 1

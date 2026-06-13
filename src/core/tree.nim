## Global tree-space state and greedy routing.
##
## This module keeps the data-plane routing decision independent of DHT storage:
## callers resolve key -> coordinates through the DHT, then call `nextHop` to
## select the neighbor whose coordinates are closest to the destination.

import std/[tables, options, times]
import ./types
import ../util/bytes

type
  LinkState* = enum lsDown, lsUp

  NeighborState* = object
    id*: NodeId
    coords*: Coordinates
    rootId*: NodeId
    state*: LinkState
    cost*: uint32
    lastSeen*: Time
    transport*: TransportKind

  TreeState* = object
    selfId*: NodeId
    rootId*: NodeId
    selfCoords*: Coordinates
    parent*: Option[NodeId]
    neighbors*: Table[NodeId, NeighborState]
    revision*: uint64

  LinkUpdate* = object
    fromId*: NodeId
    rootId*: NodeId
    coords*: Coordinates
    state*: LinkState
    revision*: uint64

proc edgeLabel*(parent, child: NodeId): uint64 =
  let raw = concatBytes(parent.bytes, child.bytes)
  result = readU64be(hash256(raw, "yggdrasil-tree-edge"), 0)
  if result == 0: result = 1

proc initTree*(selfId: NodeId): TreeState =
  result.selfId = selfId
  result.rootId = selfId
  result.selfCoords = @[]
  result.parent = none(NodeId)
  result.neighbors = initTable[NodeId, NeighborState]()
  result.revision = 1

proc isRoot*(t: TreeState): bool = t.rootId == t.selfId and t.parent.isNone

proc upNeighbors*(t: TreeState): seq[NeighborState] =
  for n in t.neighbors.values:
    if n.state == lsUp: result.add n

proc updateNeighbor*(t: var TreeState, n: NeighborState) =
  t.neighbors[n.id] = n
  inc t.revision

proc markNeighborDown*(t: var TreeState, id: NodeId) =
  if t.neighbors.hasKey(id):
    t.neighbors[id].state = lsDown
    t.neighbors[id].lastSeen = getTime()
    inc t.revision

proc removeNeighbor*(t: var TreeState, id: NodeId) =
  if t.neighbors.hasKey(id):
    t.neighbors.del(id)
    inc t.revision

proc bestRootCandidate(t: TreeState): tuple[root: NodeId, parent: Option[NodeId], coords: Coordinates] =
  ## Deterministically select the root with the lexicographically smallest node
  ## identity among visible connected components. Real Yggdrasil uses a global
  ## root-anchored tree; this deterministic policy gives simulation convergence.
  result.root = t.selfId
  result.parent = none(NodeId)
  result.coords = @[]
  for n in t.neighbors.values:
    if n.state != lsUp: continue
    let candidateRoot = n.rootId
    var better = false
    let c = cmpNodeId(candidateRoot, result.root)
    if c < 0: better = true
    elif c == 0 and result.parent.isSome:
      if n.coords.len < result.coords.len: better = true
      elif n.coords.len == result.coords.len and cmpNodeId(n.id, result.parent.get()) < 0: better = true
    if better:
      result.root = candidateRoot
      result.parent = some(n.id)
      result.coords = n.coords & @[edgeLabel(n.id, t.selfId)]

proc recomputeCoordinates*(t: var TreeState): bool =
  ## Recompute local root/coordinates. Returns true if state changed.
  let oldRoot = t.rootId
  let oldParent = t.parent
  let oldCoords = t.selfCoords
  let c = bestRootCandidate(t)
  t.rootId = c.root
  t.parent = c.parent
  t.selfCoords = c.coords
  if oldRoot != t.rootId or oldParent != t.parent or oldCoords != t.selfCoords:
    inc t.revision
    return true
  false

proc makeUpdate*(t: TreeState): LinkUpdate =
  LinkUpdate(fromId: t.selfId, rootId: t.rootId, coords: t.selfCoords,
             state: lsUp, revision: t.revision)

proc applyUpdate*(t: var TreeState, peer: NodeId, u: LinkUpdate,
                  transport = tkQuic, cost: uint32 = 1): bool =
  ## Apply a neighbor's advertised tree-space state and recompute local coords.
  var n = NeighborState(id: peer, coords: u.coords, rootId: u.rootId, state: u.state,
                        cost: cost, lastSeen: getTime(), transport: transport)
  t.updateNeighbor(n)
  result = t.recomputeCoordinates()

proc nextHop*(t: TreeState, destCoords: Coordinates): Option[NodeId] =
  ## Greedy data-plane decision: select the up neighbor closest to destination.
  ## DHT is intentionally not referenced here.
  if destCoords == t.selfCoords: return none(NodeId)
  let here = treeDistance(t.selfCoords, destCoords)
  var bestDist = high(uint64)
  var bestId: Option[NodeId] = none(NodeId)
  for n in t.neighbors.values:
    if n.state != lsUp: continue
    let d = treeDistance(n.coords, destCoords)
    if d < bestDist or (d == bestDist and (bestId.isNone or cmpNodeId(n.id, bestId.get()) < 0)):
      bestDist = d
      bestId = some(n.id)
  if bestId.isSome and bestDist < here: bestId else: none(NodeId)

proc routePath*(nodes: var Table[NodeId, TreeState], src, dst: NodeId,
                dstCoords: Coordinates, maxHops = 128): seq[NodeId] =
  ## Simulation helper: walk greedy next-hop decisions until local delivery.
  var cur = src
  result.add cur
  for _ in 0 ..< maxHops:
    if cur == dst: return
    if not nodes.hasKey(cur): break
    let hop = nodes[cur].nextHop(dstCoords)
    if hop.isNone: break
    cur = hop.get()
    if result.contains(cur):
      result.add cur
      break
    result.add cur
  
proc validateLoopFree*(path: seq[NodeId]): bool =
  var seen: seq[NodeId] = @[]
  for id in path:
    if seen.contains(id): return false
    seen.add id
  true

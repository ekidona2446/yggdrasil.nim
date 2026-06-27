## Ironwood router-state orchestrator.
##
## This is the first integration layer above the low-level Ironwood primitives.
## It is intentionally synchronous and transport-agnostic so it can be tested in
## memory and later driven by TCP/TLS/QUIC tasks. It coordinates peers, bloom
## filters, path lookup/notify, and encrypted sessions.

import std/[tables, options, times, algorithm, monotimes, strutils]
import ../core/types
import ../crypto/sodium
import ./wire
import ./bloom
import ./router
import ./peer
import ./pathfinder
import ./session

type
  RouterEventKind* = enum
    rePeerAdded,
    rePeerFrame,
    reAnnounceStored,
    reBloomUpdated,
    rePathLookupReceived,
    rePathNotifyAccepted,
    rePathBroken,
    reTrafficDelivered,
    reNoRoute,
    reDecodeError

  RouterEvent* = object
    kind*: RouterEventKind
    peer*: Option[PeerId]
    key*: Option[NodeId]
    detail*: string

  FrameAction* = object
    peerId*: PeerId
    peerKey*: NodeId
    frame*: seq[byte]

  AppDelivery* = object
    source*: NodeId
    data*: seq[byte]

  RouterStep* = object
    outbound*: seq[FrameAction]
    deliveries*: seq[AppDelivery]
    events*: seq[RouterEvent]

  RouterState* = object
    crypto*: RouterCrypto
    sessionEd*: EdKeyPair
    sessions*: SessionManager
    peers*: Table[PeerId, IronwoodPeer]
    peerByKey*: Table[NodeId, PeerId]
    portToPeer*: Table[PeerPort, PeerId]
    nextPeerId*: PeerId
    nextPort*: PeerPort
    blooms*: Blooms
    pathfinder*: Pathfinder
    announces*: Table[NodeId, RouterAnnounce]
    responses*: Table[NodeId, SigResFull]
    coordsCache*: Table[NodeId, Path]
    sentAnnounces*: Table[PeerId, seq[NodeId]]
    keyMap*: Table[NodeId, NodeId]   ## bloom-transformed key -> full public key
    ownSeq*: uint64
    lastMaintenance*: Time
    lastRefresh*: Time
    routerRefreshSeconds*: int
    routerTimeoutSeconds*: int
    refresh*: bool
    doRoot1*: bool
    doRoot2*: bool
    infoTimes*: Table[NodeId, Time]

proc toEdKeyPair*(c: RouterCrypto): EdKeyPair =
  EdKeyPair(publicKey: toEdPublic(c.publicKey), secretKey: c.secretKey)

proc initRouterState*(crypto: RouterCrypto): RouterState =
  let ed = crypto.toEdKeyPair()
  result.crypto = crypto
  result.sessionEd = ed
  result.sessions = initSessionManager(ed)
  result.peers = initTable[PeerId, IronwoodPeer]()
  result.peerByKey = initTable[NodeId, PeerId]()
  result.portToPeer = initTable[PeerPort, PeerId]()
  result.nextPeerId = 1
  result.nextPort = 1
  result.blooms = initBlooms()
  result.pathfinder = initPathfinder()
  result.announces = initTable[NodeId, RouterAnnounce]()
  result.responses = initTable[NodeId, SigResFull]()
  result.coordsCache = initTable[NodeId, Path]()
  result.sentAnnounces = initTable[PeerId, seq[NodeId]]()
  result.keyMap = initTable[NodeId, NodeId]()
  result.ownSeq = 1
  result.lastMaintenance = getTime()
  result.lastRefresh = getTime()
  result.routerRefreshSeconds = 240
  result.routerTimeoutSeconds = 480
  result.infoTimes = initTable[NodeId, Time]()
  let root = makeRootAnnounce(crypto, 1, uint64(epochTime()))
  result.announces[crypto.publicKey] = root
  result.infoTimes[crypto.publicKey] = getTime()

proc addEvent(step: var RouterStep, kind: RouterEventKind, detail = "", peer = none(PeerId), key = none(NodeId)) =
  step.events.add RouterEvent(kind: kind, peer: peer, key: key, detail: detail)

proc randomNonce(): uint64 =
  let raw = randomBytes(8)
  for b in raw: result = (result shl 8) or uint64(b)

proc action(peer: IronwoodPeer, frame: seq[byte]): FrameAction =
  FrameAction(peerId: peer.id, peerKey: peer.remoteKey, frame: frame)


proc containsNode(xs: seq[NodeId], x: NodeId): bool =
  for y in xs:
    if y == x: return true
  false

proc updateAnnounce*(r: var RouterState, ann: RouterAnnounce): bool =
  ## CRDT ordering compatible with yggdrasil-go/Yggdrasil-ng: newer seq wins;
  ## for equal seq, lexicographically smaller parent wins; for equal parent,
  ## larger nonce wins. Accepted updates invalidate coordinate cache.
  let checkOk = ann.check()
  if not checkOk:
    stderr.writeLine "[ironwood] updateAnnounce CHECK FAILED key=" & short(ann.key) & " seq=" & $ann.seq & " port=" & $ann.port
    return false
  if r.announces.hasKey(ann.key):
    let old = r.announces[ann.key]
    if old.seq > ann.seq:
      stderr.writeLine "[ironwood] updateAnnounce REJECTED: old seq " & $old.seq & " > new seq " & $ann.seq & " key=" & short(ann.key)
      return false
    if old.seq == ann.seq:
      let pc = cmpNodeId(old.parent, ann.parent)
      if pc < 0:
        stderr.writeLine "[ironwood] updateAnnounce REJECTED: same seq=" & $ann.seq & " old parent wins key=" & short(ann.key)
        return false
      # CRDT tie-break (must match yggdrasil-go network/router._update):
      # for equal seq and equal parent, the *lower* nonce wins.
      if pc == 0 and ann.nonce >= old.nonce:
        stderr.writeLine "[ironwood] updateAnnounce REJECTED: same seq=" & $ann.seq & " same parent, old nonce=" & $old.nonce & " new nonce=" & $ann.nonce & " key=" & short(ann.key)
        return false
  r.announces[ann.key] = ann
  r.infoTimes[ann.key] = getTime()
  r.coordsCache.clear()
  true

proc backwardsAncestry*(r: RouterState, key: NodeId): seq[NodeId] =
  var here = key
  while true:
    if result.containsNode(here): return
    if not r.announces.hasKey(here): return
    result.add here
    let parent = r.announces[here].parent
    if parent == here: return
    here = parent

proc ancestry*(r: RouterState, key: NodeId): seq[NodeId] =
  result = r.backwardsAncestry(key)
  result.reverse()

proc rootAndPath*(r: RouterState, key: NodeId): tuple[root: NodeId, path: Path] =
  var ports: Path
  var visited: seq[NodeId]
  var next = key
  while true:
    if visited.containsNode(next): return (key, @[])
    if not r.announces.hasKey(next): return (key, @[])
    visited.add next
    let info = r.announces[next]
    result.root = next
    if next == info.parent: break
    ports.add info.port
    next = info.parent
  ports.reverse()
  result.path = ports

proc cachedCoords*(r: var RouterState, key: NodeId): Path =
  if r.coordsCache.hasKey(key): return r.coordsCache[key]
  result = r.rootAndPath(key).path
  r.coordsCache[key] = result

proc treeDistance*(a, b: Path): uint64 =
  let endp = min(a.len, b.len)
  result = uint64(a.len + b.len)
  for i in 0 ..< endp:
    if a[i] == b[i]: result -= 2
    else: break

proc distanceToKey*(r: var RouterState, destPath: Path, key: NodeId): uint64 =
  treeDistance(destPath, r.cachedCoords(key))

proc peerCost*(r: RouterState, peerId: PeerId): uint64 =
  if r.peers.hasKey(peerId):
    let rt = r.peers[peerId].rtt.lastRtt(peerId)
    if rt.isSome: return uint64(max(rt.get(), 1))
  5000'u64

proc greedyLookup*(r: var RouterState, path: Path, watermark: var uint64): Option[PeerId] =
  let selfDist = r.distanceToKey(path, r.crypto.publicKey)
  if selfDist >= watermark: return none(PeerId)
  watermark = selfDist
  var best: Option[PeerId] = none(PeerId)
  var bestDist = high(uint64)
  var bestCost = high(uint64)
  for pid, p in r.peers:
    let dist = r.distanceToKey(path, p.remoteKey)
    if dist >= watermark: continue
    let cost = r.peerCost(pid)
    if best.isNone or cost * dist < bestCost * bestDist or
       (cost * dist == bestCost * bestDist and dist < bestDist) or
       (cost * dist == bestCost * bestDist and dist == bestDist and cost < bestCost):
      best = some(pid)
      bestDist = dist
      bestCost = cost
  if best.isSome: watermark = bestDist
  best

proc markAnnounceSent(r: var RouterState, peerId: PeerId, key: NodeId) =
  if not r.sentAnnounces.hasKey(peerId): r.sentAnnounces[peerId] = @[]
  if not r.sentAnnounces[peerId].containsNode(key): r.sentAnnounces[peerId].add key

proc wasAnnounceSent(r: RouterState, peerId: PeerId, key: NodeId): bool =
  r.sentAnnounces.hasKey(peerId) and r.sentAnnounces[peerId].containsNode(key)

proc announceFrame(ann: RouterAnnounce): seq[byte] = encodeFrame(iwProtoAnnounce, encodeAnnounce(ann.toWire()))

proc addPeer*(r: var RouterState, remoteKey: NodeId, priority: uint8 = 0): RouterStep =
  if r.peerByKey.hasKey(remoteKey):
    let pid = r.peerByKey[remoteKey]
    result.addEvent(rePeerAdded, "already-present", some(pid), some(remoteKey))
    return
  let id = r.nextPeerId
  inc r.nextPeerId
  let port = r.nextPort
  inc r.nextPort
  var p = initIronwoodPeer(id, remoteKey, r.crypto, localPort = port)
  r.peers[id] = p
  r.peerByKey[remoteKey] = id
  r.portToPeer[port] = id
  r.sentAnnounces[id] = @[]
  r.blooms.addPeer(remoteKey)
  r.blooms.setOnTree(remoteKey, true) # direct peers are eligible in the minimal router
  # Populate keyMap: TUN packets arrive with a partial key derived from the
  # peer's IPv6 address. Map it to the full key so session routing works for
  # direct peers without waiting for PathNotify.
  let peerAddr = deriveYggAddress(remoteKey)
  let peerPartial = keyPrefixForYggAddress(peerAddr)
  r.keyMap[peerPartial] = remoteKey
  result.addEvent(rePeerAdded, "port=" & $port, some(id), some(remoteKey))
  result.outbound.add r.peers[id].action(makeKeepAlive())
  # Send SigReq to the new peer (makeSigReq records lastSigReqSeq/Nonce internally).
  let sigReqSeq = r.announces[r.crypto.publicKey].seq + 1
  stderr.writeLine "[ironwood] addPeer key=" & toHex(remoteKey) & " port=" & $port & " sigReqSeq=" & $sigReqSeq
  result.outbound.add r.peers[id].action(r.peers[id].makeSigReq(sigReqSeq, randomNonce()))
  let bf = r.blooms.getBloomFor(remoteKey, r.crypto.publicKey)
  result.outbound.add r.peers[id].action(encodeFrame(iwProtoBloomFilter, bf.encode()))

proc peerIdFor*(r: RouterState, key: NodeId): Option[PeerId] =
  if r.peerByKey.hasKey(key): some(r.peerByKey[key]) else: none(PeerId)

proc bestPeerForKey(r: var RouterState, key: NodeId): Option[PeerId] =
  if r.peerByKey.hasKey(key): return some(r.peerByKey[key])
  if r.announces.hasKey(key):
    var watermark = high(uint64)
    let path = r.cachedCoords(key)
    let g = r.greedyLookup(path, watermark)
    if g.isSome: return g
  let targets = r.blooms.getMulticastTargets(r.crypto.publicKey, key)
  for t in targets:
    if r.peerByKey.hasKey(t): return some(r.peerByKey[t])
  none(PeerId)

proc routeSessionData*(r: var RouterState, dest: NodeId, data: seq[byte], step: var RouterStep) =
  ## Route session traffic to the next hop using the path from pathfinder
  ## (learned via PathNotify) or announce table, whichever is available.
  let selfCoords = r.cachedCoords(r.crypto.publicKey)
  let pathOpt = r.pathfinder.getPath(dest)
  if pathOpt.isSome:
    ## We have a path from PathNotify — use greedy lookup on it.
    let path = pathOpt.get()
    # Compute OUR distance to the destination first (this is the watermark we
    # put in the traffic frame — the next hop must be strictly closer).
    let selfDist = r.distanceToKey(path, r.crypto.publicKey)
    var watermark = selfDist
    let gp = r.greedyLookup(path, watermark)
    if gp.isSome:
      let p = r.peers[gp.get()]
      # watermark is now updated to the best peer's distance by greedyLookup.
      # But we need to send selfDist as the watermark in the frame, because
      # the watermark is the distance from the PREVIOUS hop to the destination.
      # The next hop will update it to its own distance when it forwards.
      let tr = Traffic(path: path, fromPath: selfCoords, source: r.crypto.publicKey,
                       dest: dest, watermark: selfDist, payload: data)
      stderr.writeLine "[ironwood] routeSessionData dest=" & short(dest) & " via peer=" & short(p.remoteKey) & " path=[" & coordToString(path) & "] self=[" & coordToString(selfCoords) & "] selfDist=" & $selfDist & " (pathfinder)"
      step.outbound.add p.action(encodeTrafficFrame(tr))
      return
  ## Fall back to announce-table based routing.
  let pid = r.bestPeerForKey(dest)
  if pid.isSome:
    let p = r.peers[pid.get()]
    let path2 = r.cachedCoords(dest)
    let selfPath = r.cachedCoords(r.crypto.publicKey)
    let selfDist = treeDistance(path2, selfPath)
    stderr.writeLine "[ironwood] routeSessionData dest=" & short(dest) & " path2=[" & coordToString(path2) & "] selfPath=[" & coordToString(selfPath) & "] selfDist=" & $selfDist & " announces=" & $r.announces.len
    let tr = Traffic(path: path2, fromPath: selfPath, source: r.crypto.publicKey,
                     dest: dest, watermark: selfDist, payload: data)
    stderr.writeLine "[ironwood] routeSessionData dest=" & toHex(dest) & " via peer=" & short(p.remoteKey) & " pathLen=" & $path2.len & " selfDist=" & $selfDist & " (announce)"
    step.outbound.add p.action(encodeTrafficFrame(tr))
    return
  step.addEvent(reNoRoute, "session dest=" & toHex(dest), key = some(dest))
  stderr.writeLine "[ironwood] routeSessionData dest=" & toHex(dest) & " NO ROUTE"
  discard r.pathfinder.ensureRumor(bloomTransform(dest))

proc sendPathNotifyTo*(r: var RouterState, peerId: PeerId, requester: NodeId, requestedSource: NodeId,
                       returnPath: Path): seq[FrameAction] =
  ## Create a PathNotify with our real tree coordinates and route it back to the
  ## requester via greedy lookup on the return path. Mirrors the Rust/Go
  ## handle_lookup_internal -> handle_notify_internal flow.
  if not r.peers.hasKey(peerId): return
  let ownPath = r.cachedCoords(r.crypto.publicKey)
  let sig = r.crypto.signPathInfo(uint64(epochTime()), ownPath).toArr64()
  let info = PathNotifyInfo(seq: uint64(epochTime()), path: ownPath, signature: sig)
  let notify = PathNotify(path: returnPath, watermark: high(uint64), source: requestedSource,
                          dest: requester, info: info)
  stderr.writeLine "[ironwood] sendPathNotify requester=" & toHex(requester) & " returnPath=" & coordToString(returnPath) & " ownPath=" & coordToString(ownPath)
  # Route the notify back towards the requester using greedy lookup on returnPath.
  var watermark = notify.watermark
  let pid = r.greedyLookup(notify.path, watermark)
  if pid.isSome:
    var fwd = notify
    fwd.watermark = watermark
    result.add r.peers[pid.get()].action(encodeFrame(iwProtoPathNotify, encodePathNotify(fwd)))
  else:
    # Can't greedy-route (e.g. return path is empty/short); fall back to the
    # peer that delivered the lookup so at least the immediate hop can try.
    result.add r.peers[peerId].action(encodeFrame(iwProtoPathNotify, encodePathNotify(notify)))

proc sendLookup*(r: var RouterState, dest: NodeId): RouterStep = 
  discard r.pathfinder.ensureRumor(dest)
  r.pathfinder.markLookupSent(dest)
  let fromCoords = r.cachedCoords(r.crypto.publicKey)
  let lookup = PathLookup(source: r.crypto.publicKey, dest: dest, fromPath: fromCoords)
  stderr.writeLine "[ironwood] sendLookup dest=" & toHex(dest) & " fromCoords=" & coordToString(fromCoords) & " ourAnnounces=" & $r.announces.len
  var sent = 0
  if r.peerByKey.hasKey(dest):
    let pid = r.peerByKey[dest]
    result.outbound.add r.peers[pid].action(encodeFrame(iwProtoPathLookup, encodePathLookup(lookup)))
    inc sent
  else:
    let targets = r.blooms.getMulticastTargets(r.crypto.publicKey, dest)
    for t in targets:
      if r.peerByKey.hasKey(t):
        let pid = r.peerByKey[t]
        result.outbound.add r.peers[pid].action(encodeFrame(iwProtoPathLookup, encodePathLookup(lookup)))
        inc sent
  if sent == 0:
    ## If no bloom target is known yet, try all direct peers. This is useful
    ## during early convergence and in small simulations.
    for pid, p in r.peers:
      result.outbound.add p.action(encodeFrame(iwProtoPathLookup, encodePathLookup(lookup)))
      inc sent
  result.addEvent(rePathLookupReceived, "sent=" & $sent, key = some(dest))



proc rootAndDists*(r: RouterState, key: NodeId): tuple[root: NodeId, dists: Table[NodeId, uint64]] =
  var next = key
  var dist: uint64 = 0
  result.dists = initTable[NodeId, uint64]()
  result.root = key
  while true:
    if result.dists.hasKey(next): break
    if not r.announces.hasKey(next): break
    result.root = next
    result.dists[next] = dist
    inc dist
    let parent = r.announces[next].parent
    if parent == next: break
    next = parent

proc currentParent*(r: RouterState): NodeId =
  if r.announces.hasKey(r.crypto.publicKey): r.announces[r.crypto.publicKey].parent else: r.crypto.publicKey

proc responseCost(r: RouterState, parent: NodeId): uint64 =
  if not r.peerByKey.hasKey(parent): return high(uint64)
  r.peerCost(r.peerByKey[parent])

proc adoptParent(r: var RouterState, parent: NodeId, res: SigResFull): bool =
  # The parent signed bytesForSig(ourKey, parentKey, res.seq, res.nonce, res.port).
  # We MUST use exactly res.seq/res.nonce/res.port — any change would invalidate
  # the parent's signature in ann.check().
  let ann = makeChildAnnounce(r.crypto, parent, res.seq, res.nonce, res.port, res.parentSignature.toSig64())
  let ok = r.updateAnnounce(ann)
  if ok:
    # Track the seq so future SigReqs use at least seq+1
    r.ownSeq = max(r.ownSeq, res.seq + 1)
  stderr.writeLine "[ironwood] adoptParent parent=" & short(parent) & " seq=" & $res.seq & " port=" & $res.port & " accepted=" & $ok
  ok

proc becomeRoot(r: var RouterState): bool =
  # Use the maximum of ownSeq and stored seq+1 to avoid going backwards.
  let newSeq = max(r.ownSeq, r.announces[r.crypto.publicKey].seq + 1)
  r.ownSeq = newSeq + 1
  let ann = makeRootAnnounce(r.crypto, newSeq, randomNonce())
  let ok = r.updateAnnounce(ann)
  stderr.writeLine "[ironwood] becomeRoot seq=" & $newSeq & " accepted=" & $ok
  ok

proc expireInfos*(r: var RouterState) =
  let now = getTime()
  var expired: seq[NodeId]
  for key, t in r.infoTimes:
    let age = int((now - t).inSeconds)
    if key == r.crypto.publicKey:
      if age >= r.routerRefreshSeconds: r.refresh = true
    elif age >= r.routerTimeoutSeconds:
      expired.add key
  for key in expired:
    r.infoTimes.del(key)
    r.announces.del(key)
    r.coordsCache.clear()
    for pid in r.sentAnnounces.keys:
      var kept: seq[NodeId]
      for k in r.sentAnnounces[pid]:
        if k != key: kept.add k
      r.sentAnnounces[pid] = kept

proc clearSigReqState*(r: var RouterState) =
  r.responses.clear()
  for _, p in r.peers.mpairs:
    p.lastSigReqSeq = 0
    p.lastSigReqNonce = 0

proc fixParent*(r: var RouterState): RouterStep =
  ## Parent/root selection loop inspired by Yggdrasil-ng `Router::fix`.
  ## It uses response/announce state, avoids loops, picks the smallest reachable
  ## root, then chooses an RTT-weighted best parent. The doRoot1/doRoot2 flags
  ## mimic the two-step fallback before becoming root.
  r.expireInfos()
  let selfKey = r.crypto.publicKey
  let current = r.currentParent()
  var bestRoot = selfKey
  var bestParent = selfKey
  var bestCost = high(uint64)

  if current != selfKey and r.peerByKey.hasKey(current):
    let rd = r.rootAndDists(selfKey)
    if cmpNodeId(rd.root, bestRoot) < 0:
      bestRoot = rd.root
      bestParent = current
      bestCost = max(1'u64, rd.dists.getOrDefault(rd.root, 1)) * r.responseCost(current)

  for parent, res in r.responses:
    if not r.announces.hasKey(parent): continue
    let rd = r.rootAndDists(parent)
    if rd.dists.hasKey(selfKey): continue # would loop
    let parentRoot = rd.root
    let distToRoot = max(1'u64, rd.dists.getOrDefault(parentRoot, 1))
    let cost = distToRoot * r.responseCost(parent)
    let rootCmp = cmpNodeId(parentRoot, bestRoot)
    if rootCmp < 0 or
       (rootCmp == 0 and ((r.refresh and cost * 2 < bestCost) or (parent != current and cost < bestCost))) or
       (rootCmp == 0 and cost == bestCost and cmpNodeId(parent, bestParent) < 0):
      bestRoot = parentRoot
      bestParent = parent
      bestCost = cost

  let parentChanged = current != bestParent
  var changed = false
  if r.refresh or r.doRoot1 or r.doRoot2 or parentChanged or not r.announces.hasKey(selfKey):
    if bestParent != selfKey:
      # We have a valid parent candidate (bestParent != selfKey).
      # If we have a fresh response for it, adopt; otherwise stay with current.
      if r.responses.hasKey(bestParent) and bestRoot != selfKey:
        changed = r.adoptParent(bestParent, r.responses[bestParent])
        if changed:
          r.refresh = false; r.doRoot1 = false; r.doRoot2 = false
          result.addEvent(reAnnounceStored, "adopted parent=" & toHex(bestParent) & " root=" & toHex(bestRoot), key = some(selfKey))
      elif not changed:
        # Already have this parent, don't become root
        r.refresh = false; r.doRoot1 = false; r.doRoot2 = false
    else:
      # No valid parent candidate — become root (two-step fallback)
      if r.doRoot2 or not r.announces.hasKey(selfKey):
        changed = r.becomeRoot()
        r.refresh = false; r.doRoot1 = false; r.doRoot2 = false
        if changed: result.addEvent(reAnnounceStored, "became root", key = some(selfKey))
      elif not r.doRoot1:
        r.doRoot1 = true
      else:
        r.doRoot2 = true

  if changed:
    let ann = r.announces[selfKey]
    for pid, p in r.peers:
      result.outbound.add p.action(announceFrame(ann))
      r.markAnnounceSent(pid, selfKey)

proc sendReqs*(r: var RouterState): seq[FrameAction] =
  ## Send new SigReq to all peers, clearing old request/response state.
  ## Called only when needed: on peer add, on parent/root change, on refresh.
  ## Matches Go ironwood's _sendReqs.
  r.responses.clear()
  let sigReqSeq = r.announces[r.crypto.publicKey].seq + 1
  for _, p in r.peers.mpairs:
    result.add p.action(p.makeSigReq(sigReqSeq, randomNonce()))

proc maintenance*(r: var RouterState): RouterStep =
  ## Periodic orchestrator tick. Runs parent/root selection, recomputes
  ## on-tree bloom state, refreshes blooms, and gossips known announcements.
  ## SigReqs are only sent when something actually changed (parent switch,
  ## root change, periodic refresh), matching Go ironwood's behavior where
  ## _sendReqs is called from _fix only when a change occurs.
  if int((getTime() - r.lastRefresh).inSeconds) >= r.routerRefreshSeconds:
    r.refresh = true
    r.lastRefresh = getTime()
  let (myRoot, myCoords) = r.rootAndPath(r.crypto.publicKey)
  when defined(yggdebug):
    stderr.writeLine "[STATE] root=" & toHex(myRoot) & " coords=[" & myCoords.join(",") & "] parent=" & toHex(r.currentParent()) & " announces=" & $r.announces.len & " peers=" & $r.peers.len
  let fix = r.fixParent()
  result.outbound.add fix.outbound
  result.events.add fix.events

  # If fixParent triggered a change (adopted new parent, became root, or
  # refresh was processed), send new SigReqs to all peers.
  let changed = fix.events.len > 0
  if changed:
    result.outbound.add r.sendReqs()

  var parentMap = initTable[NodeId, NodeId]()
  for key, ann in r.announces: parentMap[key] = ann.parent
  let selfParent = r.currentParent()
  for item in r.blooms.fixOnTree(r.crypto.publicKey, selfParent, parentMap):
    if r.peerByKey.hasKey(item.peer):
      let pid = r.peerByKey[item.peer]
      result.outbound.add r.peers[pid].action(encodeFrame(iwProtoBloomFilter, item.filter.encode()))

  for pid, p in r.peers.mpairs:
    let bf = r.blooms.getBloomFor(p.remoteKey, r.crypto.publicKey)
    result.outbound.add p.action(encodeFrame(iwProtoBloomFilter, bf.encode()))

  for pid, p in r.peers:
    for key, ann in r.announces:
      if not r.wasAnnounceSent(pid, key):
        result.outbound.add p.action(announceFrame(ann))
        r.markAnnounceSent(pid, key)
  r.lastMaintenance = getTime()

proc sendAppData*(r: var RouterState, dest: NodeId, data: openArray[byte]): RouterStep =
  ## Resolve a partial/transformed key to the full key if possible (like Go's
  ## keyStore), then attempt to route the traffic.
  let actualDest = if r.keyMap.hasKey(dest): r.keyMap[dest] else: dest
  let resolved = r.keyMap.hasKey(dest)
  if not r.pathfinder.hasPath(actualDest) and not r.peerByKey.hasKey(actualDest):
    stderr.writeLine "[ironwood] sendAppData dest=" & toHex(dest) & " actualDest=" & toHex(actualDest) & " resolved=" & $resolved & " keyMapSize=" & $r.keyMap.len & " no path, sending lookup"
    result = r.sendLookup(dest)
    result.addEvent(reNoRoute, "queued lookup before app data", key = some(dest))
    return
  let actions = r.sessions.writeTo(toEdPublic(actualDest), data)
  stderr.writeLine "[ironwood] sendAppData dest=" & toHex(dest) & " actualDest=" & toHex(actualDest) & " resolved=" & $resolved & " keyMapSize=" & $r.keyMap.len & " sessionActions=" & $actions.len & " dataLen=" & $data.len
  for a in actions:
    case a.kind
    of oaSendToInner: r.routeSessionData(toNodeId(a.dest), a.data, result)
    of oaDeliver: result.deliveries.add AppDelivery(source: toNodeId(a.source), data: a.data)

proc handleTraffic(r: var RouterState, tr: Traffic, step: var RouterStep) =
  if tr.dest == r.crypto.publicKey:
    stderr.writeLine "[ironwood] handleTraffic FOR US src=" & short(tr.source) & " payloadLen=" & $tr.payload.len & " firstByte=" & (if tr.payload.len > 0: $tr.payload[0] else: "empty")
    let acts = r.sessions.handleData(toEdPublic(tr.source), tr.payload)
    stderr.writeLine "[ironwood] handleData returned " & $acts.len & " actions"
    for a in acts:
      case a.kind
      of oaDeliver:
        step.deliveries.add AppDelivery(source: toNodeId(a.source), data: a.data)
        step.addEvent(reTrafficDelivered, "bytes=" & $a.data.len, key = some(toNodeId(a.source)))
        stderr.writeLine "[ironwood] traffic delivered src=" & toHex(toNodeId(a.source)) & " bytes=" & $a.data.len
      of oaSendToInner:
        r.routeSessionData(toNodeId(a.dest), a.data, step)
  else:
    var routed = false
    if tr.path.len > 0:
      var watermark = tr.watermark
      let gp = r.greedyLookup(tr.path, watermark)
      if gp.isSome:
        var fwd = tr
        fwd.watermark = watermark
        step.outbound.add r.peers[gp.get()].action(encodeTrafficFrame(fwd))
        routed = true
    if not routed:
      let pid = r.bestPeerForKey(tr.dest)
      if pid.isSome:
        step.outbound.add r.peers[pid.get()].action(encodeTrafficFrame(tr))
        routed = true
    if not routed:
      step.addEvent(reNoRoute, "traffic dest=" & toHex(tr.dest), key = some(tr.dest))

proc handleFrame*(r: var RouterState, peerId: PeerId, frame: Frame): RouterStep =
  if not r.peers.hasKey(peerId):
    result.addEvent(reDecodeError, "unknown peer")
    return
  var peerStep = r.peers[peerId].handleFrame(frame)
  r.peers[peerId] = r.peers[peerId]
  for outFrame in peerStep.outbound:
    result.outbound.add r.peers[peerId].action(outFrame)
  for ev in peerStep.events:
    result.addEvent(rePeerFrame, $ev.kind & " " & ev.detail, some(peerId), ev.announceKey)

  let remoteKey = r.peers[peerId].remoteKey
  case frame.packetType
  of iwProtoAnnounce:
    let a = decodeAnnounce(frame.payload)
    if a.isSome:
      let ann = fromWireAnnounce(a.get())
      if ann.key == r.crypto.publicKey:
        # We received our OWN announce reflected from a peer.  Never store it —
        # the nonce is always different (maintenance generates a fresh random
        # nonce each tick), so CRDT comparison would reject the duplicate and
        # could previously corrupt our own state.  If the reflected seq is
        # higher than ours (node restart with lost counter), just bump our seq
        # counter to avoid being stuck with stale routing info.
        let ownAnn = r.announces.getOrDefault(r.crypto.publicKey)
        if ann.seq >= ownAnn.seq:
          # Bump our seq to be strictly higher, matching Go ironwood's
          # behaviour when it detects a stale self-announce.
          r.ownSeq = ann.seq + 1
        stderr.writeLine "[ironwood] announce key=self (skipped, ownSeq=" & $r.ownSeq & ") parent=" & toHex(ann.parent) & " seq=" & $ann.seq & " port=" & $ann.port
      else:
        let accepted = r.updateAnnounce(ann)
        stderr.writeLine "[ironwood] announce key=" & toHex(ann.key) & " parent=" & toHex(ann.parent) & " seq=" & $ann.seq & " port=" & $ann.port & " accepted=" & $accepted
        if accepted:
          r.blooms.setOnTree(remoteKey, true)
          result.addEvent(reAnnounceStored, "parent=" & toHex(ann.parent), some(peerId), some(ann.key))
          ## Gossip newly accepted announcements to other direct peers.
          for pid, p in r.peers:
            if pid != peerId and not r.wasAnnounceSent(pid, ann.key):
              result.outbound.add p.action(announceFrame(ann))
              r.markAnnounceSent(pid, ann.key)
  of iwProtoSigRes:
    let sr = decodeSigResFull(frame.payload)
    if sr.isSome:
      r.responses[remoteKey] = sr.get().value
      stderr.writeLine "[ironwood] sigres from=" & toHex(remoteKey) & " seq=" & $sr.get().value.seq & " port=" & $sr.get().value.port
  of iwProtoBloomFilter:
    let bf = decodeBloomFilter(frame.payload)
    if bf.isSome:
      r.blooms.handleBloom(remoteKey, bf.get())
      r.blooms.setOnTree(remoteKey, true)
      stderr.writeLine "[ironwood] bloom from=" & toHex(remoteKey) & " ones=" & $bf.get().countOnes() & " announces=" & $r.announces.len
      result.addEvent(reBloomUpdated, "ones=" & $bf.get().countOnes(), some(peerId), some(remoteKey))
  of iwProtoPathLookup:
    let l = decodePathLookup(frame.payload)
    if l.isSome:
      let ourXform = bloomTransform(r.crypto.publicKey)
      let destXform = bloomTransform(l.get().dest)
      let ourAddr = deriveYggAddress(r.crypto.publicKey)
      let destAddr = deriveYggAddress(l.get().dest)
      let isForUs = ourXform == destXform
      if isForUs:
        stderr.writeLine "[ironwood] PathLookup FOR US from=" & toHex(l.get().source) & " dest=" & toHex(l.get().dest) & " MATCH"
      result.addEvent(rePathLookupReceived, "dest=" & toHex(l.get().dest), some(peerId), some(l.get().source))
      if isForUs:
        let replies = r.sendPathNotifyTo(peerId, l.get().source, r.crypto.publicKey, l.get().fromPath)
        for reply in replies: result.outbound.add reply
      else:
        let targets = r.blooms.getMulticastTargets(remoteKey, l.get().dest)
        for t in targets:
          if r.peerByKey.hasKey(t):
            let pid = r.peerByKey[t]
            result.outbound.add r.peers[pid].action(encodeFrame(iwProtoPathLookup, frame.payload))
  of iwProtoPathNotify:
    let n = decodePathNotify(frame.payload)
    if n.isSome:
      stderr.writeLine "[ironwood] PathNotify from=" & toHex(n.get().source) & " dest=" & toHex(n.get().dest) & " pathLen=" & $n.get().info.path.len
      if n.get().dest == r.crypto.publicKey:
        if r.pathfinder.acceptNotify(n.get()):
          ## Map the address-derived partial key to the responder's full key.
          ## keyPrefixForYggAddress returns a 32-byte key where only the first
          ## ~16 bytes are meaningful (derived from the IPv6 address); the rest
          ## are set to 0xFF. We store the full 32-byte partial key from the
          ## responder's address for exact matching.
          let responderAddr = deriveYggAddress(n.get().source)
          let partialKey = keyPrefixForYggAddress(responderAddr)
          r.keyMap[partialKey] = n.get().source
          stderr.writeLine "[ironwood] PathNotify ACCEPTED source=" & toHex(n.get().source) & " pathLen=" & $n.get().info.path.len & " partial=" & toHex(partialKey) & " keyMapSize=" & $r.keyMap.len
          result.addEvent(rePathNotifyAccepted, "source=" & toHex(n.get().source), some(peerId), some(n.get().source))
      else:
        var pid: Option[PeerId]
        if r.peerByKey.hasKey(n.get().dest):
          pid = some(r.peerByKey[n.get().dest])
        else:
          var watermark = n.get().watermark
          pid = r.greedyLookup(n.get().path, watermark)
          if pid.isSome:
            var fwd = n.get()
            fwd.watermark = watermark
            result.outbound.add r.peers[pid.get()].action(encodeFrame(iwProtoPathNotify, encodePathNotify(fwd)))
            pid = none(PeerId)
        if pid.isSome:
          result.outbound.add r.peers[pid.get()].action(encodeFrame(iwProtoPathNotify, frame.payload))
  of iwProtoPathBroken:
    let b = decodePathBroken(frame.payload)
    if b.isSome:
      var watermark = b.get().watermark
      let pid = r.greedyLookup(b.get().path, watermark)
      if pid.isSome:
        var fwd = b.get()
        fwd.watermark = watermark
        result.outbound.add r.peers[pid.get()].action(encodeFrame(iwProtoPathBroken, encodePathBroken(fwd)))
      else:
        r.pathfinder.markBroken(b.get().source)
        result.addEvent(rePathBroken, "source=" & toHex(b.get().source), some(peerId), some(b.get().source))
  of iwTraffic:
    let tr = decodeTraffic(frame.payload)
    if tr.isSome:
      stderr.writeLine "[ironwood] traffic from=" & toHex(tr.get().source) & " dest=" & toHex(tr.get().dest) & " pathLen=" & $tr.get().path.len & " payloadLen=" & $tr.get().payload.len
      r.handleTraffic(tr.get(), result)
  else:
    discard

proc handleFrameBytes*(r: var RouterState, peerId: PeerId, data: openArray[byte]): RouterStep =
  let f = decodeFrame(data)
  if f.isNone:
    result.addEvent(reDecodeError, "bad frame")
  else:
    result = r.handleFrame(peerId, f.get())

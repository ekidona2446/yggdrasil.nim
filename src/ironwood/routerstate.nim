## Ironwood router-state orchestrator.
##
## This is the first integration layer above the low-level Ironwood primitives.
## It is intentionally synchronous and transport-agnostic so it can be tested in
## memory and later driven by TCP/TLS/QUIC tasks. It coordinates peers, bloom
## filters, path lookup/notify, and encrypted sessions.

import std/[tables, options, times, algorithm]
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
  if not ann.check(): return false
  if r.announces.hasKey(ann.key):
    let old = r.announces[ann.key]
    if old.seq > ann.seq: return false
    if old.seq == ann.seq:
      let pc = cmpNodeId(old.parent, ann.parent)
      if pc < 0: return false
      if pc == 0 and ann.nonce <= old.nonce: return false
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
  result.addEvent(rePeerAdded, "port=" & $port, some(id), some(remoteKey))
  result.outbound.add r.peers[id].action(makeKeepAlive())
  # SigReq seq MUST be announces[selfKey].seq + 1, matching Go ironwood's _newReq
  let sigReqSeq = r.announces[r.crypto.publicKey].seq + 1
  stderr.writeLine "[ironwood] addPeer key=" & short(remoteKey) & " port=" & $port & " sigReqSeq=" & $sigReqSeq
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
  let pid = r.bestPeerForKey(dest)
  if pid.isNone:
    step.addEvent(reNoRoute, "session dest=" & short(dest), key = some(dest))
    stderr.writeLine "[ironwood] routeSessionData dest=" & short(dest) & " NO ROUTE"
    discard r.pathfinder.ensureRumor(dest)
    return
  let p = r.peers[pid.get()]
  let path = r.pathfinder.getPath(dest).get(r.cachedCoords(dest))
  let tr = Traffic(path: path, fromPath: r.cachedCoords(r.crypto.publicKey), source: r.crypto.publicKey,
                   dest: dest, watermark: high(uint64), payload: data)
  stderr.writeLine "[ironwood] routeSessionData dest=" & short(dest) & " via peer=" & short(p.remoteKey) & " pathLen=" & $path.len
  step.outbound.add p.action(encodeTrafficFrame(tr))

proc sendPathNotifyTo*(r: var RouterState, peerId: PeerId, requester: NodeId, requestedSource: NodeId,
                       returnPath: Path): Option[FrameAction] =
  if not r.peers.hasKey(peerId): return none(FrameAction)
  let ownPath: Path = @[]
  let sig = r.crypto.signPathInfo(uint64(epochTime()), ownPath).toArr64()
  let info = PathNotifyInfo(seq: uint64(epochTime()), path: ownPath, signature: sig)
  let notify = PathNotify(path: returnPath, watermark: high(uint64), source: requestedSource,
                          dest: requester, info: info)
  some(r.peers[peerId].action(encodeFrame(iwProtoPathNotify, encodePathNotify(notify))))

proc sendLookup*(r: var RouterState, dest: NodeId): RouterStep =
  discard r.pathfinder.ensureRumor(dest)
  r.pathfinder.markLookupSent(dest)
  let lookup = PathLookup(source: r.crypto.publicKey, dest: dest, fromPath: @[])
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
  let ann = makeChildAnnounce(r.crypto, parent, res.seq, res.nonce, res.port, res.parentSignature.toSig64())
  let ok = r.updateAnnounce(ann)
  stderr.writeLine "[ironwood] adoptParent parent=" & short(parent) & " seq=" & $res.seq & " port=" & $res.port & " accepted=" & $ok
  ok

proc becomeRoot(r: var RouterState): bool =
  # Must use announces[selfKey].seq + 1 like Go ironwood's _becomeRoot
  let newSeq = r.announces[r.crypto.publicKey].seq + 1
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
    if bestParent != selfKey and r.responses.hasKey(bestParent) and bestRoot != selfKey:
      changed = r.adoptParent(bestParent, r.responses[bestParent])
      if changed:
        r.refresh = false; r.doRoot1 = false; r.doRoot2 = false
        result.addEvent(reAnnounceStored, "adopted parent=" & short(bestParent) & " root=" & short(bestRoot), key = some(selfKey))
    if not changed:
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

proc maintenanceSigReqs*(r: var RouterState): seq[FrameAction] =
  r.responses.clear()
  # SigReq seq MUST be announces[selfKey].seq + 1, matching Go ironwood's _newReq
  let sigReqSeq = r.announces[r.crypto.publicKey].seq + 1
  for _, p in r.peers.mpairs:
    result.add p.action(p.makeSigReq(sigReqSeq, randomNonce()))

proc maintenance*(r: var RouterState): RouterStep =
  ## Periodic orchestrator tick. Sends SigReq refreshes, runs parent/root
  ## selection, recomputes on-tree bloom state, refreshes blooms, and gossips
  ## known announcements that have not yet been sent to each peer.
  if int((getTime() - r.lastRefresh).inSeconds) >= r.routerRefreshSeconds:
    r.refresh = true
    r.lastRefresh = getTime()
  let fix = r.fixParent()
  result.outbound.add fix.outbound
  result.events.add fix.events

  var parentMap = initTable[NodeId, NodeId]()
  for key, ann in r.announces: parentMap[key] = ann.parent
  let selfParent = r.currentParent()
  for item in r.blooms.fixOnTree(r.crypto.publicKey, selfParent, parentMap):
    if r.peerByKey.hasKey(item.peer):
      let pid = r.peerByKey[item.peer]
      result.outbound.add r.peers[pid].action(encodeFrame(iwProtoBloomFilter, item.filter.encode()))

  result.outbound.add r.maintenanceSigReqs()
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
  if not r.pathfinder.hasPath(dest) and not r.peerByKey.hasKey(dest):
    stderr.writeLine "[ironwood] sendAppData dest=" & short(dest) & " no path, sending lookup"
    result = r.sendLookup(dest)
    result.addEvent(reNoRoute, "queued lookup before app data", key = some(dest))
    return
  let actions = r.sessions.writeTo(toEdPublic(dest), data)
  stderr.writeLine "[ironwood] sendAppData dest=" & short(dest) & " sessionActions=" & $actions.len & " dataLen=" & $data.len
  for a in actions:
    case a.kind
    of oaSendToInner: r.routeSessionData(toNodeId(a.dest), a.data, result)
    of oaDeliver: result.deliveries.add AppDelivery(source: toNodeId(a.source), data: a.data)

proc handleTraffic(r: var RouterState, tr: Traffic, step: var RouterStep) =
  if tr.dest == r.crypto.publicKey:
    let acts = r.sessions.handleData(toEdPublic(tr.source), tr.payload)
    for a in acts:
      case a.kind
      of oaDeliver:
        step.deliveries.add AppDelivery(source: toNodeId(a.source), data: a.data)
        step.addEvent(reTrafficDelivered, "bytes=" & $a.data.len, key = some(toNodeId(a.source)))
        stderr.writeLine "[ironwood] traffic delivered src=" & short(toNodeId(a.source)) & " bytes=" & $a.data.len
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
      step.addEvent(reNoRoute, "traffic dest=" & short(tr.dest), key = some(tr.dest))

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
      let accepted = r.updateAnnounce(ann)
      stderr.writeLine "[ironwood] announce key=" & short(ann.key) & " parent=" & short(ann.parent) & " seq=" & $ann.seq & " port=" & $ann.port & " accepted=" & $accepted
      if accepted:
        r.blooms.setOnTree(remoteKey, true)
        result.addEvent(reAnnounceStored, "parent=" & short(ann.parent), some(peerId), some(ann.key))
        ## Gossip newly accepted announcements to other direct peers.
        for pid, p in r.peers:
          if pid != peerId and not r.wasAnnounceSent(pid, ann.key):
            result.outbound.add p.action(announceFrame(ann))
            r.markAnnounceSent(pid, ann.key)
  of iwProtoSigRes:
    let sr = decodeSigResFull(frame.payload)
    if sr.isSome:
      r.responses[remoteKey] = sr.get().value
      stderr.writeLine "[ironwood] sigres from=" & short(remoteKey) & " seq=" & $sr.get().value.seq & " port=" & $sr.get().value.port
  of iwProtoBloomFilter:
    let bf = decodeBloomFilter(frame.payload)
    if bf.isSome:
      r.blooms.handleBloom(remoteKey, bf.get())
      r.blooms.setOnTree(remoteKey, true)
      result.addEvent(reBloomUpdated, "ones=" & $bf.get().countOnes(), some(peerId), some(remoteKey))
  of iwProtoPathLookup:
    let l = decodePathLookup(frame.payload)
    if l.isSome:
      result.addEvent(rePathLookupReceived, "dest=" & short(l.get().dest), some(peerId), some(l.get().source))
      if l.get().dest == r.crypto.publicKey:
        let reply = r.sendPathNotifyTo(peerId, l.get().source, r.crypto.publicKey, l.get().fromPath)
        if reply.isSome: result.outbound.add reply.get()
      else:
        let targets = r.blooms.getMulticastTargets(remoteKey, l.get().dest)
        for t in targets:
          if r.peerByKey.hasKey(t):
            let pid = r.peerByKey[t]
            result.outbound.add r.peers[pid].action(encodeFrame(iwProtoPathLookup, frame.payload))
  of iwProtoPathNotify:
    let n = decodePathNotify(frame.payload)
    if n.isSome:
      if n.get().dest == r.crypto.publicKey:
        if r.pathfinder.acceptNotify(n.get()):
          result.addEvent(rePathNotifyAccepted, "source=" & short(n.get().source), some(peerId), some(n.get().source))
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
        result.addEvent(rePathBroken, "source=" & short(b.get().source), some(peerId), some(b.get().source))
  of iwTraffic:
    let tr = decodeTraffic(frame.payload)
    if tr.isSome: r.handleTraffic(tr.get(), result)
  else:
    discard

proc handleFrameBytes*(r: var RouterState, peerId: PeerId, data: openArray[byte]): RouterStep =
  let f = decodeFrame(data)
  if f.isNone:
    result.addEvent(reDecodeError, "bad frame")
  else:
    result = r.handleFrame(peerId, f.get())

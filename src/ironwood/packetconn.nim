## Async Chronos-based PacketConn for Yggdrasil.
##
## Central overlay abstraction:
## - Application data enters/exits through readFrom/writeTo
## - Peer connections registered via handleConn
## - Background router actor processes frames and runs maintenance

import std/[tables, options, monotimes, times]
import chronos
import ../core/types
import ./wire
import ./router
import ./routerstate
import ./bloom
import ./session
import ../transport/asyncpeer
import ./routertypes

const
  RecvChannelSize* = 512
  RouterChannelSize* = 4096
  MaintenanceIntervalMs* = 1000
  RouterRefreshSeconds* = 240
  RouterTimeoutSeconds* = 480

type
  PathNotifyCb* = proc(key: NodeId) {.gcsafe, raises: [].}

  PacketConn* = ref object
    crypto*: RouterCrypto
    state*: RouterState
    deliveryQueue*: AsyncQueue[AppDelivery]
    peers*: Table[PeerId, AsyncPeer]
    peerByKey*: Table[NodeId, PeerId]
    routerChan*: AsyncQueue[RouterMessage]
    maintenanceFut*: Future[void]
    running*: bool
    pathNotifyCb*: PathNotifyCb
    pendingOutbound*: Table[PeerId, seq[seq[byte]]]  ## buffered frames for peers not yet in pc.peers

proc newPacketConn*(crypto: RouterCrypto): PacketConn =
  result = PacketConn(
    crypto: crypto,
    state: initRouterState(crypto),
    deliveryQueue: newAsyncQueue[AppDelivery](RecvChannelSize),
    routerChan: newAsyncQueue[RouterMessage](RouterChannelSize),
    running: false,
  )

proc mtu*(pc: PacketConn): uint64 =
  min(65535'u64 * 2 - 1, 65535'u64)

proc localAddr*(pc: PacketConn): NodeId =
  pc.crypto.publicKey

proc dispatchOutbound(pc: PacketConn, step: RouterStep) =
  for action in step.outbound:
    if pc.peers.hasKey(action.peerId):
      pc.peers[action.peerId].sendFrame(action.frame)
    else:
      # Peer's AsyncPeer not registered yet (addPeer via channel race).
      # Buffer the frame; it will be flushed once handleConn creates the peer.
      if not pc.pendingOutbound.hasKey(action.peerId):
        pc.pendingOutbound[action.peerId] = @[]
      pc.pendingOutbound[action.peerId].add(action.frame)

proc dispatchDeliveries(pc: PacketConn, step: RouterStep) =
  for d in step.deliveries:
    try:
      pc.deliveryQueue.addLastNoWait(d)
    except AsyncQueueFullError:
      discard

proc dispatchEvents(pc: PacketConn, step: RouterStep) =
  for ev in step.events:
    if ev.kind == rePathNotifyAccepted and ev.key.isSome and pc.pathNotifyCb != nil:
      try: pc.pathNotifyCb(ev.key.get())
      except CatchableError: discard

proc processRouterMessage(pc: PacketConn, msg: RouterMessage) =
  {.cast(gcsafe).}:
    try:
      case msg.kind
      of rmAddPeer:
        if not pc.state.peerByKey.hasKey(msg.peerKey):
          let step = pc.state.addPeer(msg.peerKey, msg.priority)
          pc.dispatchOutbound(step)
          pc.dispatchDeliveries(step)
      of rmRemovePeer:
        if pc.state.peers.hasKey(msg.peerId):
          pc.state.peers.del(msg.peerId)
        if pc.state.peerByKey.hasKey(msg.peerKey) and
           pc.state.peerByKey[msg.peerKey] == msg.peerId:
          pc.state.peerByKey.del(msg.peerKey)
        pc.state.sentAnnounces.del(msg.peerId)
        pc.state.blooms.removePeer(msg.peerKey)
      of rmHandleFrame:
        if pc.state.peers.hasKey(msg.peerId):
          let step = pc.state.handleFrame(msg.peerId, msg.frame)
          pc.dispatchOutbound(step)
          pc.dispatchDeliveries(step)
          pc.dispatchEvents(step)
      of rmSendTraffic:
        try:
          let step = pc.state.sendAppData(msg.traffic.dest, msg.traffic.payload)
          pc.dispatchOutbound(step)
          pc.dispatchDeliveries(step)
        except CatchableError as e:
          stderr.writeLine "[packetconn] rmSendTraffic error: " & e.msg
      of rmMaintenanceTick:
        let step = pc.state.maintenance()
        pc.dispatchOutbound(step)
        pc.dispatchDeliveries(step)
      of rmForceRefresh:
        pc.state.refresh = true
        pc.state.doRoot1 = true
        pc.state.doRoot2 = true
        pc.state.lastRefresh = getTime() - initDuration(seconds = RouterRefreshSeconds)
    except CatchableError:
      discard

proc routerActorLoop(pc: PacketConn) {.async.} =
  var lastTick = getMonoTime()
  while pc.running:
    let now = getMonoTime()
    let elapsed = int((now - lastTick).inMilliseconds)
    let waitMs = max(1, MaintenanceIntervalMs - elapsed)
    
    let sleepFut = sleepAsync(chronos.milliseconds(waitMs))
    let recvFut = pc.routerChan.popFirst()
    let completed = await race(recvFut, sleepFut)
    
    {.cast(gcsafe).}:
      if completed == recvFut:
        try:
          let msg = recvFut.read()
          try:
            pc.processRouterMessage(msg)
          except Exception:
            discard
        except CatchableError:
          discard
      else:
        try:
          pc.processRouterMessage(RouterMessage(kind: rmMaintenanceTick))
        except Exception:
          discard
        lastTick = getMonoTime()

proc readFrom*(pc: PacketConn, buf: ptr byte, bufLen: int): Future[(int, NodeId)] {.async.} =
  let delivery = await pc.deliveryQueue.popFirst()
  let n = min(bufLen, delivery.data.len)
  if n > 0:
    copyMem(buf, unsafeAddr delivery.data[0], n)
  result = (n, delivery.source)

proc writeTo*(pc: PacketConn, dest: NodeId, data: seq[byte]): Future[void] {.async.} = 
  stderr.writeLine "[packetconn] writeTo dest=" & short(dest) & " dataLen=" & $data.len
  let msg = RouterMessage(
    kind: rmSendTraffic,
    traffic: Traffic(
      path: @[], fromPath: @[],
      source: pc.crypto.publicKey, dest: dest,
      watermark: high(uint64), payload: data,
    )
  )
  try:
    pc.routerChan.addLastNoWait(msg)
  except AsyncQueueFullError:
    await pc.routerChan.addLast(msg)

proc handleConn*(pc: PacketConn, peerKey: NodeId, transport: StreamTransport,
                 priority: uint8 = 0): Future[void] {.async.} =
  ## Handle a new or re-connected peer backed by a raw StreamTransport.
  ## addPeer is done synchronously (single-threaded async is safe) to avoid
  ## the race where the routerChan consumer hasn't processed the addPeer
  ## message yet.  The outbound frames from addPeer are dispatched directly.
  # Register peer synchronously via router channel, then poll for the
  # peer to appear.  The channel approach avoids Nim's strict exception
  # tracking with {.async.} while still serializing router state access.
  let addMsg = RouterMessage(kind: rmAddPeer, peerKey: peerKey, priority: priority)
  await pc.routerChan.addLast(addMsg)
  
  var pid: PeerId = 0
  for attempt in 0 ..< 200:
    {.cast(gcsafe).}:
      let pidOpt = pc.state.peerIdFor(peerKey)
      if pidOpt.isSome:
        pid = pidOpt.get()
        break
    await sleepAsync(chronos.milliseconds(10))
  
  if pid == 0:
    raise newException(ValueError, "peer not registered after addPeer")
  
  if pc.peers.hasKey(pid):
    let oldPeer = pc.peers[pid]
    oldPeer.close()
    pc.peers.del(pid)
  
  let peer = newAsyncPeer(pid, peerKey, transport, pc.routerChan)
  pc.peers[pid] = peer
  pc.peerByKey[peerKey] = pid
  # Flush any frames that were buffered before the AsyncPeer existed
  if pc.pendingOutbound.hasKey(pid):
    let count = pc.pendingOutbound[pid].len
    for i, frame in pc.pendingOutbound[pid]:
      stderr.writeLine "[packetconn] flushing frame[" & $i & "] len=" & $frame.len & " firstBytes=" & (if frame.len >= 2: $frame[0] & "," & $frame[1] else: $frame[0]) & " for peer=" & short(peerKey)
      peer.sendFrame(frame)
    pc.pendingOutbound.del(pid)
    stderr.writeLine "[packetconn] flushed " & $count & " pending frames for peer=" & short(peerKey)
  
  try:
    await peer.run()
  finally:
    pc.peers.del(pid)
    if pc.peerByKey.hasKey(peerKey) and pc.peerByKey[peerKey] == pid:
      pc.peerByKey.del(peerKey)
    let rmMsg = RouterMessage(kind: rmRemovePeer, peerId: pid, peerKey: peerKey)
    try:
      pc.routerChan.addLastNoWait(rmMsg)
    except AsyncQueueFullError:
      asyncSpawn pc.routerChan.addLast(rmMsg)

proc handleConnStream*(pc: PacketConn, peerKey: NodeId,
                      reader: AsyncStreamReader, writer: AsyncStreamWriter,
                      transport: StreamTransport,
                      priority: uint8 = 0): Future[void] {.async.} =
  ## Handle a peer backed by an AsyncStreamReader/Writer (e.g. WebSocket or TLS).
  let addMsg = RouterMessage(kind: rmAddPeer, peerKey: peerKey, priority: priority)
  await pc.routerChan.addLast(addMsg)
  
  var pid: PeerId = 0
  for attempt in 0 ..< 200:
    {.cast(gcsafe).}:
      let pidOpt = pc.state.peerIdFor(peerKey)
      if pidOpt.isSome:
        pid = pidOpt.get()
        break
    await sleepAsync(chronos.milliseconds(10))
  
  if pid == 0:
    raise newException(ValueError, "peer not registered after addPeer")
  
  if pc.peers.hasKey(pid):
    let oldPeer = pc.peers[pid]
    oldPeer.close()
    pc.peers.del(pid)
  
  let peer = newAsyncPeerStream(pid, peerKey, reader, writer, transport, pc.routerChan)
  pc.peers[pid] = peer
  pc.peerByKey[peerKey] = pid
  # Flush any frames that were buffered before the AsyncPeer existed
  if pc.pendingOutbound.hasKey(pid):
    let count = pc.pendingOutbound[pid].len
    for frame in pc.pendingOutbound[pid]:
      peer.sendFrame(frame)
    pc.pendingOutbound.del(pid)
    stderr.writeLine "[packetconn] flushed " & $count & " pending frames for stream peer=" & short(peerKey)
  
  try:
    await peer.run()
  finally:
    pc.peers.del(pid)
    if pc.peerByKey.hasKey(peerKey) and pc.peerByKey[peerKey] == pid:
      pc.peerByKey.del(peerKey)
    let rmMsg = RouterMessage(kind: rmRemovePeer, peerId: pid, peerKey: peerKey)
    try:
      pc.routerChan.addLastNoWait(rmMsg)
    except AsyncQueueFullError:
      asyncSpawn pc.routerChan.addLast(rmMsg)

proc start*(pc: PacketConn) {.async.} =
  pc.running = true
  pc.maintenanceFut = routerActorLoop(pc)

proc close*(pc: PacketConn) {.async.} =
  pc.running = false
  for pid, peer in pc.peers:
    peer.close()
  pc.peers.clear()
  pc.peerByKey.clear()

## Async Chronos-based peer reader/writer for Ironwood.
##
## Each peer connection runs two concurrent loops:
## - Reader: reads frames from the stream, dispatches to router channel
## - Writer: receives frames via an AsyncQueue, writes with keepalive
##
## Works with both raw StreamTransport (TCP) and TLS-wrapped streams.

import std/[monotimes, options]
import chronos
import chronos/streams/asyncstream
import ../core/types
import ../ironwood/wire
import ../ironwood/router
import ../ironwood/routertypes

const
  PeerWriterQueueSize* = 512
  MaxFrameSize* = 1_048_576   ## 1 MiB max frame size
  WriteTimeoutMs* = 10_000    ## 10s write timeout
  KeepaliveIntervalMs* = 60_000  ## 60s idle keepalive

type
  AsyncPeer* = ref object
    id*: PeerId
    remoteKey*: NodeId
    transport*: StreamTransport      ## For raw TCP connections
    reader*: AsyncStreamReader       ## For TLS or raw connections  
    writer*: AsyncStreamWriter       ## For TLS or raw connections
    writerQueue*: AsyncQueue[seq[byte]]
    running*: bool
    routerChan*: AsyncQueue[RouterMessage]
    lastReceived*: MonoTime
    ownsTransport*: bool             ## True if we created the reader/writer from transport

proc newAsyncPeer*(id: PeerId, remoteKey: NodeId, transport: StreamTransport,
                   routerChan: AsyncQueue[RouterMessage]): AsyncPeer =
  ## Create a peer backed by a raw StreamTransport (TCP).
  let reader = newAsyncStreamReader(transport)
  let writer = newAsyncStreamWriter(transport)
  result = AsyncPeer(
    id: id,
    remoteKey: remoteKey,
    transport: transport,
    reader: reader,
    writer: writer,
    writerQueue: newAsyncQueue[seq[byte]](PeerWriterQueueSize),
    running: false,
    routerChan: routerChan,
    lastReceived: getMonoTime(),
    ownsTransport: true,
  )

proc newAsyncPeerStream*(id: PeerId, remoteKey: NodeId,
                          reader: AsyncStreamReader, writer: AsyncStreamWriter,
                          transport: StreamTransport,
                          routerChan: AsyncQueue[RouterMessage]): AsyncPeer =
  ## Create a peer with pre-built AsyncStreamReader/AsyncStreamWriter (for TLS).
  result = AsyncPeer(
    id: id,
    remoteKey: remoteKey,
    transport: transport,
    reader: reader,
    writer: writer,
    writerQueue: newAsyncQueue[seq[byte]](PeerWriterQueueSize),
    running: false,
    routerChan: routerChan,
    lastReceived: getMonoTime(),
    ownsTransport: false,
  )

proc sendFrame*(peer: AsyncPeer, frame: seq[byte]) =
  try:
    peer.writerQueue.addLastNoWait(frame)
  except AsyncQueueFullError:
    discard

proc readUvarintFromReader(r: AsyncStreamReader): Future[uint64] {.async.} =
  var value: uint64 = 0
  var shift: int = 0
  var buf: array[1, byte]
  for _ in 0 ..< 10:
    let n = await r.readOnce(addr buf[0], 1)
    if n == 0:
      raise newException(ValueError, "connection closed reading uvarint")
    let byteVal = buf[0]
    if shift >= 63 and byteVal > 1'u8:
      raise newException(ValueError, "uvarint overflow")
    value = value or (uint64(byteVal and 0x7f'u8) shl shift)
    if (byteVal and 0x80'u8) == 0:
      return value
    shift += 7
  raise newException(ValueError, "uvarint too long")

proc readFrameFromReader*(r: AsyncStreamReader): Future[Frame] {.async.} =
  let length = await readUvarintFromReader(r)
  if length == 0 or length > uint64(MaxFrameSize):
    raise newException(ValueError, "invalid frame length: " & $length)
  
  let contentLen = int(length)
  var content = newSeq[byte](contentLen)
  var offset = 0
  while offset < contentLen:
    let n = await r.readOnce(addr content[offset], contentLen - offset)
    if n == 0:
      raise newException(ValueError, "connection closed reading frame")
    offset += n
  
  let pt = toPacketType(content[0])
  if pt.isNone:
    raise newException(ValueError, "unknown packet type: " & $content[0])
  
  var payload: seq[byte]
  if contentLen > 1:
    payload = newSeq[byte](contentLen - 1)
    copyMem(addr payload[0], addr content[1], contentLen - 1)
  
  result = Frame(packetType: pt.get(), payload: payload, consumed: contentLen)

proc readerLoop(peer: AsyncPeer) {.async.} =
  while peer.running:
    try:
      let frame = await readFrameFromReader(peer.reader)
      peer.lastReceived = getMonoTime()
      
      let msg = RouterMessage(
        kind: rmHandleFrame,
        peerId: peer.id,
        peerKey: peer.remoteKey,
        frame: frame,
      )
      try:
        peer.routerChan.addLastNoWait(msg)
      except AsyncQueueFullError:
        asyncSpawn peer.routerChan.addLast(msg)
    except CancelledError:
      break
    except CatchableError as e:
      stderr.writeLine "[asyncpeer] reader error peer=" & short(peer.remoteKey) & ": " & e.msg
      break

proc writerLoop(peer: AsyncPeer) {.async.} =
  let keepalive = encodeFrame(iwKeepAlive, [])
  
  while peer.running:
    let sleepFut = sleepAsync(chronos.milliseconds(KeepaliveIntervalMs))
    let recvFut = peer.writerQueue.popFirst()
    let completed = await race(recvFut, sleepFut)
    
    if completed == recvFut:
      let frameData = recvFut.read()
      try:
        await peer.writer.write(frameData)
      except CatchableError as e:
        stderr.writeLine "[asyncpeer] writer error peer=" & short(peer.remoteKey) & ": " & e.msg
        break
    else:
      try:
        await peer.writer.write(keepalive)
      except CatchableError:
        break

proc run*(peer: AsyncPeer) {.async.} =
  peer.running = true
  
  let readerFut = readerLoop(peer)
  let writerFut = writerLoop(peer)
  
  let completed = await race(readerFut, writerFut)
  
  if completed == readerFut:
    writerFut.cancelSoon()
  else:
    readerFut.cancelSoon()
  
  try: await readerFut
  except CancelledError: discard
  try: await writerFut
  except CancelledError: discard
  
  peer.running = false
  try:
    peer.reader.close()
    peer.writer.close()
  except CatchableError: discard
  try: peer.transport.close()
  except CatchableError: discard

proc close*(peer: AsyncPeer) =
  peer.running = false
  try:
    peer.reader.close()
    peer.writer.close()
  except CatchableError: discard
  try: peer.transport.close()
  except CatchableError: discard

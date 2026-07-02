## QUIC peer transport using nim-lsquic.
##
## Exposes an outgoing QUIC bidirectional stream as a Chronos StreamTransport via
## a local socketpair, so the existing Yggdrasil metadata handshake and AsyncPeer
## code can run unchanged.  This mirrors yggdrasil-go's model: QUIC connection,
## then one stream carrying the normal link byte stream.

import std/[options, posix, sets]
import chronos
import chronos/transports/stream
import lsquic as lq
import lsquic/certificateverifier/insecure
import ../core/types
import ../ironwood/router

type
  QuicPeerConnection* = ref object
    uri*: PeerUri
    connected*: bool
    nodeId*: NodeId

  QuicManager* = ref object
    crypto*: RouterCrypto
    tlsConfig*: lq.TLSConfig
    client*: lq.QuicClient
    initialized*: bool

  QuicBridgeState* = ref object
    manager*: QuicManager
    conn*: lq.Connection
    stream*: lq.Stream
    appTransport*: StreamTransport
    pumpTransport*: StreamTransport
    appFd*: cint
    pumpFd*: cint
    running*: bool
    quicToAppFut*: Future[void]
    appToQuicFut*: Future[void]

proc newQuicManager*(crypto: RouterCrypto): QuicManager =
  QuicManager(crypto: crypto, initialized: false)

proc setupQuicManager*(mgr: QuicManager) =
  if mgr.initialized: return
  # nim-lsquic does not initialize the C library implicitly. Without this,
  # lsquic aborts in lsquic_hash.c:get_seed() on the first QUIC dial.
  lq.initializeLsquic(client = true, server = false)
  var alpn = initHashSet[string]()
  # yggdrasil-go leaves NextProtos empty for QUIC; nim-lsquic accepts an empty
  # ALPN wire too.  Keep the set empty for interoperability.
  mgr.tlsConfig = lq.TLSConfig.new(
    alpn = alpn,
    certVerifier = Opt.some(lq.CertificateVerifier(InsecureCertificateVerifier.init()))
  )
  mgr.client = lq.QuicClient.new(mgr.tlsConfig)
  mgr.initialized = true

proc quicToAppLoop(st: QuicBridgeState) {.async.} =
  var buf: array[32768, byte]
  while st.running:
    let n = await st.stream.readOnce(addr buf[0], buf.len)
    if n <= 0: break
    discard await st.pumpTransport.write(addr buf[0], n)

proc appToQuicLoop(st: QuicBridgeState) {.async.} =
  var buf: array[32768, byte]
  while st.running:
    let n = await st.pumpTransport.readOnce(addr buf[0], buf.len)
    if n <= 0: break
    var data = newSeq[byte](n)
    copyMem(addr data[0], addr buf[0], n)
    await st.stream.write(data)

proc createQuicBridge*(mgr: QuicManager; host: string; port: int;
                       timeoutMs = 7000): Future[Option[tuple[state: QuicBridgeState, transport: StreamTransport]]] {.async.} =
  try:
    mgr.setupQuicManager()
    let address = initTAddress(host, port)
    let conn = await mgr.client.dial(address).wait(chronos.milliseconds(timeoutMs))
    let qs = await conn.openStream().wait(chronos.milliseconds(timeoutMs))

    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      conn.close()
      raise newException(OSError, "socketpair failed")

    let app = fromPipe(AsyncFD(fds[0]))
    let pump = fromPipe(AsyncFD(fds[1]))
    let st = QuicBridgeState(
      manager: mgr, conn: conn, stream: qs,
      appTransport: app, pumpTransport: pump,
      appFd: fds[0], pumpFd: fds[1], running: true)
    st.quicToAppFut = quicToAppLoop(st)
    st.appToQuicFut = appToQuicLoop(st)
    return some((st, app))
  except CatchableError as e:
    echo "[QUIC] bridge creation failed: ", e.msg
    return none(tuple[state: QuicBridgeState, transport: StreamTransport])

proc close*(st: QuicBridgeState) {.raises: [].} =
  if st.isNil: return
  st.running = false
  try: st.quicToAppFut.cancelSoon()
  except Exception: discard
  try: st.appToQuicFut.cancelSoon()
  except Exception: discard
  try: st.conn.close()
  except Exception: discard
  try: st.appTransport.close()
  except Exception: discard
  try: st.pumpTransport.close()
  except Exception: discard
  try: discard posix.close(st.appFd)
  except Exception: discard
  try: discard posix.close(st.pumpFd)
  except Exception: discard

proc dialQuicPeer*(mgr: QuicManager, uri: PeerUri): Future[QuicPeerConnection] {.async.} =
  let br = await mgr.createQuicBridge(uri.host, uri.port)
  result = QuicPeerConnection(uri: uri, connected: br.isSome)

proc listenQuic*(mgr: var QuicManager, host = "0.0.0.0", port = 443): Future[QuicPeerConnection] {.async.} =
  echo "[QUIC] listener not implemented yet"
  result = QuicPeerConnection(connected: false)

proc getConnection*(mgr: QuicManager, nodeId: NodeId): Option[QuicPeerConnection] =
  none(QuicPeerConnection)

proc closeQuicPeer*(peer: var QuicPeerConnection) =
  peer.connected = false

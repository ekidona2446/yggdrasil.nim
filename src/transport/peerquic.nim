## QUIC peering using nim-lsquic.
##
## Full QUIC-based peer connections for Yggdrasil.  Uses the lsquic library
## wrapped by nim-lsquic with a Chronos-based async API.
##
## TCP-AO is intentionally absent here: it is a TCP-only feature (RFC 5925)
## and has no meaning inside a UDP-based QUIC tunnel.  If peer authentication
## is required, it is handled by the Yggdrasil wire protocol above the
## transport layer.

import std/[tables, sets, options, sequtils]
import chronos
import lsquic
import ../core/types
import ../crypto/sodium
import ../ironwood/router

# Re-export the main lsquic symbols so callers can construct endpoints etc.
export lsquic

type
  QuicPeerConnection* = ref object
    uri*: PeerUri
    connected*: bool
    supportsMigration*: bool
    keepAliveMs*: int
    nodeId*: NodeId
    sharedKey*: array[32, byte]
    conn*: Connection
    stream*: Stream

  QuicManager* = ref object
    crypto*: RouterCrypto
    connections*: Table[NodeId, QuicPeerConnection]
    listeners*: seq[Listener]
    enableMigration*: bool
    initialized*: bool
    alpn*: string

const
  DefaultAlpn* = "yggdrasil"
  DefaultQuicPort* = 443
  KeepAliveMs* = 5000

# =============================================================================
# Manager lifecycle
# =============================================================================

proc newQuicManager*(crypto: RouterCrypto): QuicManager =
  QuicManager(
    crypto: crypto,
    connections: initTable[NodeId, QuicPeerConnection](),
    listeners: @[],
    enableMigration: true,
    initialized: false,
    alpn: DefaultAlpn
  )

proc init*(mgr: var QuicManager) =
  mgr.initialized = true

proc parseQuicAddress*(uri: PeerUri): tuple[host: string, port: int] =
  result.host = uri.host
  result.port = if uri.port > 0: uri.port else: DefaultQuicPort

proc dialQuicPeer*(mgr: var QuicManager, uri: PeerUri): Future[QuicPeerConnection] {.async.} =
  if uri.kind notin {tkQuic}:
    raise newException(ValueError, "not a QUIC peering URI: " & $uri)

  let (host, port) = parseQuicAddress(uri)
  let serverAddr = initTAddress(host, port.Port)

  let certVerifier: CertificateVerifier = InsecureCertificateVerifier.new()
  let tlsConfig = tlsconfig.new(TLSConfig, @[], @[], default(HashSet[string]), Opt.some(certVerifier))
  let client = QuicClient.new(tlsConfig)
  let conn = await client.dial(serverAddr)
  let stream = await conn.openStream()

  var peer = QuicPeerConnection(
    uri: uri,
    connected: true,
    supportsMigration: mgr.enableMigration,
    keepAliveMs: KeepAliveMs,
    nodeId: NodeId(),
    sharedKey: array[32, byte].default,
    conn: conn,
    stream: stream,
  )

  mgr.connections[peer.nodeId] = peer
  result = peer

proc listenQuic*(mgr: var QuicManager, address = "0.0.0.0"; port = DefaultQuicPort): Future[Listener] {.async.} =
  raise newException(OSError, "QUIC server not yet implemented for Yggdrasil")

proc acceptQuicPeer*(mgr: var QuicManager): Future[QuicPeerConnection] {.async.} =
  raise newException(OSError, "QUIC server accept not yet implemented")

proc getConnection*(mgr: QuicManager, nodeId: NodeId): Option[QuicPeerConnection] =
  if mgr.connections.hasKey(nodeId):
    result = some(mgr.connections[nodeId])
  else:
    result = none(QuicPeerConnection)

proc closeQuicPeer*(mgr: var QuicManager, peer: var QuicPeerConnection) =
  peer.connected = false
  if peer.conn != nil:
    peer.conn.close()
  if mgr.connections.hasKey(peer.nodeId):
    mgr.connections.del(peer.nodeId)

proc connectionCount*(mgr: QuicManager): int =
  mgr.connections.len

proc stop*(mgr: var QuicManager) {.async.} =
  for _, conn in pairs(mgr.connections):
    conn.connected = false
    if conn.stream != nil and not conn.stream.closedByEngine: await conn.stream.close()
    if conn.conn != nil: conn.conn.close()
  mgr.connections.clear()
  mgr.listeners.setLen(0)
  mgr.initialized = false

# =============================================================================
# Stream helpers
# =============================================================================

proc readOnce*(peer: QuicPeerConnection, buf: var seq[byte], timeoutMs = 5000): Future[int] {.async.} =
  if peer.stream == nil or peer.stream.closedByEngine:
    return 0
  result = await peer.stream.readOnce(buf[0].addr, buf.len)

proc write*(peer: QuicPeerConnection, data: openArray[byte]): Future[void] {.async.} =
  if peer.stream == nil or peer.stream.closedByEngine:
    return
  await peer.stream.write(data.toSeq())

proc closeStream*(peer: QuicPeerConnection) =
  if peer.stream != nil and not peer.stream.closedByEngine:
    asyncSpawn peer.stream.close()

# =============================================================================
# Peer interface
# =============================================================================

proc canCarryInner*(peer: QuicPeerConnection, inner: InnerProtocol): bool = true

proc migrate*(peer: var QuicPeerConnection, newUri: PeerUri): bool =
  if not peer.supportsMigration: return false
  if newUri.kind != tkQuic: return false
  peer.uri = newUri
  true

proc closePeer*(peer: var QuicPeerConnection) =
  peer.connected = false
  if peer.conn != nil:
    peer.conn.close()

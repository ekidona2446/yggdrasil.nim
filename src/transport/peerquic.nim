## QUIC peer transport (nim-lsquic integration)
##
## When nim-lsquic is installed, real implementation is used.
## Otherwise this is a stub so the project compiles.

import std/[tables, options, strutils]
import chronos
import ../core/types
import ../crypto/sodium
import ../ironwood/router

type
  QuicPeerConnection* = ref object
    uri*: PeerUri
    connected*: bool
    nodeId*: NodeId

  QuicManager* = ref object
    crypto*: RouterCrypto
    connections*: Table[NodeId, QuicPeerConnection]
    initialized*: bool

proc newQuicManager*(crypto: RouterCrypto): QuicManager =
  QuicManager(
    crypto: crypto,
    connections: initTable[NodeId, QuicPeerConnection](),
    initialized: false
  )

proc setupQuicManager*(mgr: var QuicManager) =
  echo "[QUIC] lsquic not installed — QUIC stub active"
  mgr.initialized = true

proc dialQuicPeer*(mgr: var QuicManager, uri: PeerUri): Future[QuicPeerConnection] {.async.} =
  echo "[QUIC] stub: would dial ", uri
  result = QuicPeerConnection(uri: uri, connected: false)

proc listenQuic*(mgr: var QuicManager, host = "0.0.0.0", port = 443): Future[QuicPeerConnection] {.async.} =
  echo "[QUIC] stub: listening not implemented"
  result = QuicPeerConnection(connected: false)

proc getConnection*(mgr: QuicManager, nodeId: NodeId): Option[QuicPeerConnection] =
  none(QuicPeerConnection)

proc closeQuicPeer*(peer: var QuicPeerConnection) =
  peer.connected = false

## QUIC peering boundary.
##
## QUIC/UDP is the preferred outer transport, and is mandatory when carrying
## inner TCP traffic to avoid TCP-over-TCP meltdown.

import ../core/types

type
  QuicPeer* = object
    uri*: PeerUri
    connected*: bool
    supportsMigration*: bool
    keepAliveSeconds*: int

proc openQuicPeer*(uri: PeerUri): QuicPeer =
  if uri.kind notin {tkQuic, tkUdp}:
    raise newException(ValueError, "not a QUIC/UDP peering URI")
  QuicPeer(uri: uri, connected: false, supportsMigration: uri.kind == tkQuic,
           keepAliveSeconds: 5)

proc canCarryInner*(p: QuicPeer, inner: InnerProtocol): bool = true

proc connect*(p: var QuicPeer) =
  ## Production: nim-quic + Chronos handshake/listen.
  p.connected = true

proc migrate*(p: var QuicPeer, newUri: PeerUri): bool =
  ## Production: QUIC connection migration. Dev backend simply swaps URI.
  if not p.supportsMigration: return false
  if newUri.kind != tkQuic: return false
  p.uri = newUri
  true

proc close*(p: var QuicPeer) = p.connected = false

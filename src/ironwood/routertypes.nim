## Shared router message types for the async actor model.

import ../core/types
import ./wire
import ./router  # PeerId

type
  RouterMessageKind* = enum
    rmAddPeer           ## Register a new peer connection
    rmRemovePeer        ## Peer disconnected
    rmHandleFrame       ## Incoming frame from a peer
    rmSendTraffic       ## Outbound application data
    rmMaintenanceTick   ## Periodic maintenance timer
    rmForceRefresh      ## Force router refresh

  RouterMessage* = object
    kind*: RouterMessageKind
    peerId*: PeerId
    peerKey*: NodeId
    peerPort*: PeerPort  ## Local ironwood port to remove from portToPeer on disconnect
    frame*: Frame
    traffic*: TrafficPacket
    priority*: uint8     ## Peer priority for addPeer

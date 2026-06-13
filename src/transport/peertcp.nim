## TCP/TLS/WebSocket/Unix peering boundary and TCP-AO policy hooks.
##
## The data-plane selector must call `canCarryInner` before selecting a stream
## transport. This enforces the non-negotiable no-TCP-over-TCP rule.

import ../core/types

type
  TcpAoStatus* = enum taoUnsupported, taoAvailable, taoEnabled

  TcpPeer* = object
    uri*: PeerUri
    tcpAo*: TcpAoStatus
    connected*: bool

proc tcpAoSupported*(): TcpAoStatus =
  when defined(linux):
    ## Placeholder: production should probe TCP_AO sockopts.
    taoAvailable
  else:
    taoUnsupported

proc canCarryInner*(outer: TransportKind, inner: InnerProtocol): bool =
  ## Hard fail for TCP-over-TCP. TLS, WebSocket, and Unix sockets are stream
  ## transports and are therefore disallowed for inner TCP payloads.
  if inner == ipTcp and outer.isStreamTransport: return false
  true

proc requireCanCarry*(outer: TransportKind, inner: InnerProtocol) =
  if not canCarryInner(outer, inner):
    raise newException(ValueError, "policy violation: refusing TCP-over-TCP encapsulation")

proc openTcpPeer*(uri: PeerUri, inner: InnerProtocol): TcpPeer =
  if uri.kind notin {tkTcp, tkTls, tkWebSocket, tkUnix}:
    raise newException(ValueError, "not a TCP/stream peering URI")
  requireCanCarry(uri.kind, inner)
  result.uri = uri
  result.tcpAo = tcpAoSupported()
  result.connected = false

proc enableTcpAo*(p: var TcpPeer, key: openArray[byte]): bool =
  ## Linux TCP-AO integration point. Returns false if not supported.
  when defined(linux):
    if key.len == 0: return false
    p.tcpAo = taoEnabled
    true
  else:
    false

proc connect*(p: var TcpPeer) =
  ## Production: Chronos async TCP/TLS/WebSocket dial/listen.
  p.connected = true

proc close*(p: var TcpPeer) = p.connected = false

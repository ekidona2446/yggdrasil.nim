## TCP/TLS/WebSocket/Unix peering boundary and TCP-AO policy hooks.
##
## The data-plane selector must call `canCarryInner` before selecting a stream
## transport. This enforces the non-negotiable no-TCP-over-TCP rule.

import std/net
import ../core/types
import ../core/tcp_ao
import ../core/tcp_ao

type
  TcpAoStatus* = enum taoUnsupported, taoAvailable, taoEnabled

  TcpPeer* = object
    uri*: PeerUri
    tcpAo*: TcpAoStatus
    connected*: bool
    aoKey*: TcpAoKey

proc tcpAoStatus*(): TcpAoStatus =
  if isTcpAoSupported():
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
  result.tcpAo = tcpAoStatus()
  result.connected = false

proc enableTcpAo*(p: var TcpPeer, key: openArray[byte]): bool =
  ## Linux TCP-AO integration point. Returns false if not supported.
  if not isTcpAoSupported():
    return false
  if key.len == 0:
    return false
  p.aoKey = newTcpAoKey(0, 1, "hmac-sha-1-96", key)
  p.tcpAo = taoEnabled
  true

proc applyTcpAo*(p: TcpPeer, sock: Socket): bool =
  ## Apply the configured TCP-AO key to a live socket. Must be called after
  ## the TCP connection is established.
  if p.tcpAo != taoEnabled:
    return false
  applyTcpAoToSocket(sock, p.aoKey)

proc connect*(p: var TcpPeer) =
  ## Production: Chronos async TCP/TLS/WebSocket dial/listen.
  p.connected = true

proc close*(p: var TcpPeer) = p.connected = false

## WebSocket peer transport (nim-websock integration)
##
## When nim-websock is installed, real implementation is used.
## Otherwise this is a stub so the project compiles.

import std/[strutils, options]
import chronos
import chronos/transports/stream

# Stub types when the real package is not available
type
  WebSocket* = ref object
    connected*: bool

  WsPeerConnection* = ref object
    uri*: string
    connected*: bool
    ws*: WebSocket
    host*: string
    port*: int
    path*: string

proc wsHandshake*(transp: StreamTransport, host: string, port: int, path: string = "/"): Future[WebSocket] {.async.} =
  echo "[WS] WebSocket handshake stub (install nim-websock for real support)"
  result = WebSocket(connected: false)

proc dialWs*(host: string, port: int, path = "/"): Future[WebSocket] {.async.} =
  echo "[WS] dialWs stub called for ", host, ":", port
  result = WebSocket(connected: false)

proc dialWss*(host: string, port: int, path = "/"): Future[WebSocket] {.async.} =
  echo "[WS] dialWss stub called for ", host, ":", port
  result = WebSocket(connected: false)

proc newWsPeerConnection*(uri: string, host: string, port: int, path = "/"): Future[WsPeerConnection] {.async.} =
  result = WsPeerConnection(
    uri: uri,
    connected: false,
    host: host,
    port: port,
    path: path
  )

proc close*(peer: WsPeerConnection) =
  discard

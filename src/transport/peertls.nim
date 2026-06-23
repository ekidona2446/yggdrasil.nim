## TLS 1.3 peer transport using WolfSSL
##
## Replaces previous OpenSSL thread-bridge implementation.
## Provides TLS 1.3 for `tls://` and `wss://` peers.

import std/[os, options, posix, net]
import chronos
import chronos/transports/stream
import ../crypto/wolfssl

type
  TlsBridgeConfig* = object
    host*: string
    port*: int
    sni*: string
    timeoutMs*: int

  TlsBridgeState* = ref object
    config: TlsBridgeConfig
    wolfCtx*: WolfSSLContext
    wolfSess*: WolfSSLSession
    chronosFd*: cint
    sockFd*: SocketHandle
    running*: bool

proc createTlsBridge*(config: TlsBridgeConfig): Option[tuple[state: TlsBridgeState, transport: StreamTransport]] =
  try:
    if not loadWolfSSL():
      echo "[TLS] WolfSSL library not found. TLS disabled."
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    let ctx = initWolfSSL()
    var sock = newSocket()
    sock.connect(config.host, Port(config.port), timeout = config.timeoutMs)

    let sockFd = sock.getFd()
    var sess = newWolfSSLSession(ctx, config.host, config.port)

    if not connectWolfSSL(sess, cint(sockFd)):
      sock.close()
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    # Create a pipe for Chronos <-> WolfSSL
    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      sock.close()
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    let state = TlsBridgeState(
      config: config,
      wolfCtx: ctx,
      wolfSess: sess,
      chronosFd: fds[0],
      sockFd: sockFd,
      running: true
    )

    let transport = fromPipe(AsyncFD(fds[0]))
    return some((state, transport))
  except CatchableError as e:
    echo "[TLS] WolfSSL bridge creation failed: ", e.msg
    return none(tuple[state: TlsBridgeState, transport: StreamTransport])

proc close*(state: TlsBridgeState) =
  state.running = false
  try:
    closeWolfSSL(state.wolfSess)
    discard posix.close(state.chronosFd)
  except: discard

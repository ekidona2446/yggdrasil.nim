## TLS 1.3 peer transport using WolfSSL.
##
## Chronos does not expose a WolfSSL transport directly, so this module creates a
## local socketpair.  Chronos talks to one end and two small native threads pump
## bytes between the other end and the WolfSSL session.

import std/[options, posix, net]
import chronos
import chronos/transports/stream
import ../crypto/wolfssl

type
  TlsBridgeConfig* = object
    host*: string
    port*: int
    sni*: string
    timeoutMs*: int

  PumpArgs = object
    ssl: pointer
    fd: cint

  TlsBridgeState* = ref object
    config: TlsBridgeConfig
    wolfCtx*: WolfSSLContext
    wolfSess*: WolfSSLSession
    chronosFd*: cint
    pumpFd*: cint
    sockFd*: SocketHandle
    upThread*: Thread[PumpArgs]
    downThread*: Thread[PumpArgs]
    running*: bool

proc writeAll(fd: cint; p: pointer; n: int): bool {.gcsafe.} =
  var off = 0
  while off < n:
    let wrote = posix.write(fd, cast[pointer](cast[uint](p) + uint(off)), n - off)
    if wrote <= 0: return false
    off += wrote
  true

proc pipeToTls(args: PumpArgs) {.thread, gcsafe.} =
  var buf: array[16384, byte]
  while true:
    let n = posix.read(args.fd, addr buf[0], buf.len)
    if n <= 0: break
    var off = 0
    while off < n:
      let wrote = rawWriteWolfSSL(args.ssl, addr buf[off], n - off)
      if wrote <= 0: return
      off += wrote

proc tlsToPipe(args: PumpArgs) {.thread, gcsafe.} =
  var buf: array[16384, byte]
  while true:
    let n = rawReadWolfSSL(args.ssl, addr buf[0], buf.len)
    if n <= 0: break
    if not writeAll(args.fd, addr buf[0], n): break

proc createTlsBridge*(config: TlsBridgeConfig): Option[tuple[state: TlsBridgeState, transport: StreamTransport]] =
  try:
    if not loadWolfSSL():
      echo "[TLS] WolfSSL library not found. TLS disabled."
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    let ctx = initWolfSSL(client = true)
    var sock = newSocket()
    sock.connect(config.host, Port(config.port), timeout = config.timeoutMs)

    let sockFd = sock.getFd()
    var sess = newWolfSSLSession(ctx, config.host, config.port, config.sni)

    if not connectWolfSSL(sess, cint(sockFd)):
      sock.close()
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      closeWolfSSL(sess)
      sock.close()
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])

    let state = TlsBridgeState(
      config: config,
      wolfCtx: ctx,
      wolfSess: sess,
      chronosFd: fds[0],
      pumpFd: fds[1],
      sockFd: sockFd,
      running: true
    )

    createThread(state.upThread, pipeToTls, PumpArgs(ssl: sess.ssl, fd: fds[1]))
    createThread(state.downThread, tlsToPipe, PumpArgs(ssl: sess.ssl, fd: fds[1]))

    let transport = fromPipe(AsyncFD(fds[0]))
    return some((state, transport))
  except CatchableError as e:
    echo "[TLS] WolfSSL bridge creation failed: ", e.msg
    return none(tuple[state: TlsBridgeState, transport: StreamTransport])

proc close*(state: TlsBridgeState) {.raises: [].} =
  if state.isNil: return
  state.running = false
  try: discard posix.shutdown(SocketHandle(state.pumpFd), SHUT_RDWR) except Exception: discard
  try: discard posix.shutdown(SocketHandle(state.chronosFd), SHUT_RDWR) except Exception: discard
  try: closeWolfSSL(state.wolfSess) except Exception: discard
  try: discard posix.close(state.pumpFd) except Exception: discard
  try: discard posix.close(state.chronosFd) except Exception: discard
  try: state.wolfCtx.cleanupWolfSSL() except Exception: discard

## TLS 1.3 bridge for Yggdrasil peer connections.
##
## Yggdrasil Go nodes require TLS 1.3 for `tls://` peers. Chronos's built-in
## BearSSL only supports TLS 1.2, so we use OpenSSL (via `std/net` with `-d:ssl`)
## in background threads and bridge data to/from Chronos through a Unix socketpair.
##
## Architecture:
##   Chronos <-> socketpair[0] (fromPipe) <-> socketpair[1] <-> two threads <-> OpenSSL <-> network
##
## Two dedicated threads:
## - Read thread:  SSL recv -> write to bridgeFd  (data flows: network -> Chronos)
## - Write thread: read from bridgeFd -> SSL send (data flows: Chronos -> network)
##
## This avoids select()-with-SSL pitfalls (SSL has internal buffers that don't
## correlate with fd readability, so a single select()-driven loop can deadlock).

import std/[os, net, strutils, options, posix]
import chronos
import chronos/transports/stream

when not defined(ssl):
  when not defined(nimdoc):
    {.error: "peertls.nim requires -d:ssl flag (OpenSSL linkage)".}

type
  TlsBridgeConfig* = object
    host*: string        ## Remote host (IP or domain)
    port*: int           ## Remote port
    sni*: string         ## TLS SNI hostname (empty = no SNI)
    timeoutMs*: int      ## Connect/handshake timeout

  TlsBridgeState* = ref object
    config: TlsBridgeConfig
    readThread: Thread[TlsBridgeState]
    writeThread: Thread[TlsBridgeState]
    chronosFd: cint      ## FD for Chronos to use (socketpair[0])
    bridgeFd: cint       ## FD for bridge threads (socketpair[1])
    sslSock: Socket
    running: bool
    errorFlag: bool      ## Set by either thread on error -> signal shutdown

# ── TLS bridge threads ──────────────────────────────────────────────────────

proc tlsReadThread(state: TlsBridgeState) {.thread.} =
  ## Read thread: reads decrypted data from SSL socket, writes to bridgeFd.
  let sock = state.sslSock
  let bridgeFd = state.bridgeFd
  var buf = newString(65536)
  
  while state.running and not state.errorFlag:
    try:
      let n = sock.recv(buf, buf.len, timeout = 30000)
      if n == 0:
        # Timeout or no data — check if it's really EOF
        # sock.recv returns 0 on timeout too, so we need to check
        # if the socket is still connected
        if not state.running: break
        # It might be a timeout, not EOF — continue
        continue
      # Write all received data to bridgeFd for Chronos to pick up
      var written = 0
      while written < n and not state.errorFlag:
        let w = posix.write(bridgeFd, addr buf[written], n - written)
        if w <= 0:
          state.errorFlag = true
          break
        written += w
    except CatchableError:
      # SSL error — real disconnect
      break
  
  state.errorFlag = true
  discard posix.shutdown(SocketHandle(bridgeFd), SHUT_WR)

proc tlsWriteThread(state: TlsBridgeState) {.thread.} =
  ## Write thread: reads plaintext from bridgeFd, sends via SSL socket.
  ## Blocking loop: read(socketpair) -> SSL_send.
  let sock = state.sslSock
  let bridgeFd = state.bridgeFd
  var buf = newString(65536)
  
  while state.running and not state.errorFlag:
    try:
      let n = posix.read(bridgeFd, addr buf[0], buf.len)
      if n <= 0:
        # Chronos closed the connection or error
        break
      # Send all data through SSL
      sock.send(buf[0 ..< n])
    except CatchableError:
      break
  
  state.errorFlag = true

# ── Public API ──────────────────────────────────────────────────────────────

proc createTlsBridge*(config: TlsBridgeConfig): Option[tuple[state: TlsBridgeState, transport: StreamTransport]] =
  ## Create a TLS bridge:
  ## 1. Connect to remote host via TCP using OpenSSL
  ## 2. Perform TLS 1.3 handshake (cert verification disabled, like Go's InsecureSkipVerify)
  ## 3. Create a Unix socketpair
  ## 4. Start read and write bridge threads
  ## Returns the bridge state and a StreamTransport connected to socketpair[0].
  
  try:
    # Create SSL context (no cert verification — Yggdrasil uses self-signed certs)
    var ctx = newContext(protVersion = protSSLv23, verifyMode = CVerifyNone)
    
    # Connect to remote
    var sock = newSocket()
    sock.connect(config.host, Port(config.port), timeout = config.timeoutMs)
    
    # TLS handshake with optional SNI
    let sni = if config.sni.len > 0: config.sni else: ""
    wrapConnectedSocket(ctx, sock, handshake = handshakeAsClient, hostname = sni)
    
    # Create socketpair
    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      sock.close()
      return none(tuple[state: TlsBridgeState, transport: StreamTransport])
    
    let state = TlsBridgeState(
      config: config,
      chronosFd: fds[0],
      bridgeFd: fds[1],
      sslSock: sock,
      running: true,
      errorFlag: false,
    )
    
    # Start both bridge threads
    createThread(state.readThread, tlsReadThread, state)
    createThread(state.writeThread, tlsWriteThread, state)
    
    # Create Chronos StreamTransport from socketpair[0]
    let transport = fromPipe(AsyncFD(fds[0]))
    
    return some((state, transport))
  except CatchableError:
    return none(tuple[state: TlsBridgeState, transport: StreamTransport])

proc close*(state: TlsBridgeState) =
  ## Shut down the TLS bridge.
  state.running = false
  state.errorFlag = true
  # Closing chronosFd will cause the write thread to see EOF on bridgeFd
  try:
    discard posix.close(state.chronosFd)
  except CatchableError: discard

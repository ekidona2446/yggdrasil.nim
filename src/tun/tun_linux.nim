## TUN adapter — Linux /dev/net/tun implementation.
##
## Creates a TUN interface, assigns the Yggdrasil IPv6 address, and bridges
## packet I/O between the kernel interface and Chronos.
##
## Data plane wiring (in yggdrasil.nim):
##   TUN read  -> PacketConn.writeTo()  (ingress: kernel -> overlay)
##   PacketConn.readFrom() -> TUN write (egress:  overlay -> kernel)
##
## The kernel TUN fd is NOT directly pollable by Chronos in a portable way, so
## we bridge it through an AF_UNIX SOCK_STREAM socketpair with a 4-byte
## big-endian length prefix per packet (the same proven pattern used by the TLS
## bridge in transport/peertls.nim, but framed to preserve packet boundaries).
##
##   readThread :  tunFd.read() -> [len][packet] -> bridgeFd -> (asyncFd) -> Chronos
##   writeThread:  bridgeFd <- [len][packet] <- (asyncFd) <- Chronos  -> tunFd.write()

import std/[os, strutils, posix, options]
import chronos
import chronos/transports/stream
import ../core/types
import ../util/ipnet

when not defined(linux):
  {.error: "tun_linux.nim is Linux-only".}

# ── Linux TUN constants ─────────────────────────────────────────────────────

const
  TUNSETIFF = 0x400454ca'u32
  IFF_TUN = 0x0001
  IFF_NO_PI = 0x1000
  TUN_MAX_PACKET = 65535 + 14
  YggPrefix* = "200::/7"

type
  TunIfReq = object
    ifr_name: array[16, char]
    ifr_flags: uint16

  TunPlatform* = enum tpLinux

  TunConfig* = object
    enable*: bool
    name*: string
    mtu*: int
    ipv6*: string
    ipv4*: string
    tunFd*: cint

  TunAdapter* = ref object
    cfg*: TunConfig
    platform*: TunPlatform
    opened*: bool
    tunFd*: cint
    ifName*: string
    running*: bool
    readThread*: Thread[TunAdapter]
    writeThread*: Thread[TunAdapter]
    asyncFd*: cint        ## socketpair end used by Chronos (StreamTransport)
    bridgeFd*: cint       ## socketpair end used by the I/O threads
    transport*: StreamTransport

# ── small helpers ───────────────────────────────────────────────────────────

proc setCloexec(fd: cint) =
  let flags = fcntl(fd, F_GETFD, 0)
  if flags >= 0: discard fcntl(fd, F_SETFD, flags or FD_CLOEXEC)

proc setNonblocking(fd: cint) =
  let flags = fcntl(fd, F_GETFL, 0)
  if flags >= 0: discard fcntl(fd, F_SETFL, flags or O_NONBLOCK)

proc setSocketBufferSize(fd: cint, size: int) =
  var sz: cint = cint(size)
  var lenv: SockLen = SockLen(sizeof(sz))
  discard posix.setsockopt(SocketHandle(fd), SOL_SOCKET, SO_SNDBUF, addr sz, lenv)
  discard posix.setsockopt(SocketHandle(fd), SOL_SOCKET, SO_RCVBUF, addr sz, lenv)

proc writeAll(fd: cint, data: pointer, n: int): bool =
  ## Blocking write of exactly n bytes. Returns false on fatal error.
  var off = 0
  while off < n:
    let w = posix.write(fd, cast[pointer](cast[uint](data) + uint(off)),
                        n - off)
    if w > 0: off += int(w)
    elif w == 0: return false
    else:
      if errno == EINTR: continue
      return false
  true

proc tryWriteNonblocking(fd: cint, data: pointer, n: int): bool =
  ## Non-blocking write. Returns true if all bytes written, false if the
  ## socket buffer is full (caller should drop the packet to avoid deadlock).
  var off = 0
  while off < n:
    let w = posix.write(fd, cast[pointer](cast[uint](data) + uint(off)),
                        n - off)
    if w > 0: off += int(w)
    elif w == 0: return false
    else:
      if errno == EINTR: continue
      if errno == EAGAIN or errno == EWOULDBLOCK: return false
      return false
  true

proc readAll(fd: cint, data: pointer, n: int): bool =
  ## Read exactly n bytes. Returns false on EOF/fatal error.
  ## NOTE: the bridge fd is opened in non-blocking mode (so the read thread's
  ## writes never block), which means read() here can legitimately return
  ## EAGAIN/EWOULDBLOCK when no data is available yet. Treat that as "wait and
  ## retry" rather than a fatal error — otherwise the TUN write thread would
  ## die on the first idle read and inbound packets would silently stop being
  ## delivered to the kernel.
  var off = 0
  while off < n:
    let r = posix.read(fd, cast[pointer](cast[uint](data) + uint(off)),
                       n - off)
    if r > 0: off += r
    elif r == 0: return false
    else:
      if errno == EINTR: continue
      if errno == EAGAIN or errno == EWOULDBLOCK:
        # No data ready; block briefly on the fd then retry.
        var pfd = TPollfd(fd: fd, events: POLLIN, revents: 0)
        discard posix.poll(addr pfd, 1, 1000)
        continue
      return false
  true

# ── TUN background threads ──────────────────────────────────────────────────

proc tunReadThread(tun: TunAdapter) {.thread.} =
  ## Read whole packets from the TUN fd and push length-prefixed frames to the
  ## bridge socket so Chronos can pick them up asynchronously. Uses non-blocking
  ## writes to avoid deadlock when the async consumer is slow (packets are
  ## dropped if the bridge buffer is full).
  var buf = newString(TUN_MAX_PACKET)
  var hdr: array[4, byte]
  while tun.running:
    let n = posix.read(tun.tunFd, addr buf[0], buf.len)
    if n > 0:
      let m = int(n)
      hdr[0] = byte((m shr 24) and 0xff)
      hdr[1] = byte((m shr 16) and 0xff)
      hdr[2] = byte((m shr 8) and 0xff)
      hdr[3] = byte(m and 0xff)
      # Non-blocking write: drop packet if buffer is full rather than blocking.
      if tryWriteNonblocking(tun.bridgeFd, addr hdr[0], 4) and
         tryWriteNonblocking(tun.bridgeFd, addr buf[0], m):
        discard
      else:
        # Buffer full, drop packet to prevent deadlock.
        discard
    else:
      if not tun.running: break
      if errno == EINTR: continue
      discard posix.usleep(1000)

proc tunWriteThread(tun: TunAdapter) {.thread.} =
  ## Read length-prefixed frames from the bridge socket and write them as whole
  ## packets to the TUN fd.
  var hdr: array[4, byte]
  var buf = newString(TUN_MAX_PACKET)
  while tun.running:
    if not readAll(tun.bridgeFd, addr hdr[0], 4): break
    let m = int((uint32(hdr[0]) shl 24) or (uint32(hdr[1]) shl 16) or
                (uint32(hdr[2]) shl 8) or uint32(hdr[3]))
    if m <= 0 or m > buf.len:
      continue
    if not readAll(tun.bridgeFd, addr buf[0], m): break
    if not writeAll(tun.tunFd, addr buf[0], m):
      if not tun.running: break
      discard posix.usleep(1000)

# ── TUN device management ───────────────────────────────────────────────────

proc openTunFd(name: string): tuple[fd: cint, actual: string, err: cint] =
  ## Try to allocate a TUN interface with the given name.
  let fd = posix.open("/dev/net/tun", O_RDWR)
  if fd < 0:
    return (cint(-1), "", errno)
  var req: TunIfReq
  zeroMem(addr req, sizeof(req))
  for i in 0 ..< min(name.len, 15):
    req.ifr_name[i] = name[i]
  req.ifr_flags = uint16(IFF_TUN or IFF_NO_PI)
  if ioctl(fd, culong(TUNSETIFF), addr req) < 0:
    let e = errno
    discard close(fd)
    return (cint(-1), "", e)
  var actual = ""
  for c in req.ifr_name:
    if c == '\0': break
    actual.add c
  result = (fd, actual, cint(0))

proc candidateNames(requested: string): seq[string] =
  ## Build a list of interface names to try. Honours the requested name first,
  ## then falls back to ygg0..ygg9 on conflicts (e.g. another Yggdrasil already
  ## owns "ygg0").
  let base = if requested.len > 0: requested else: "ygg0"
  result.add(base)
  for i in 0 ..< 10:
    let n = "ygg" & $i
    if n notin result:
      result.add(n)

proc openTun*(cfg: TunConfig): TunAdapter =
  ## Open a TUN device on Linux. Robust to an already-claimed interface name
  ## (falls back to the next free yggN) or pre-opened fd (from Android),
  ## and sets up the async I/O bridge.
  result = TunAdapter(
    cfg: cfg, platform: tpLinux, opened: false,
    tunFd: cint(-1), running: false,
    asyncFd: cint(-1), bridgeFd: cint(-1),
  )
  if not cfg.enable:
    return

  # Async bridge socketpair.
  var fds: array[2, cint]
  if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
    raise newException(OSError, "TUN socketpair failed: " & $strerror(errno))
  setCloexec(fds[0]); setCloexec(fds[1])
  setNonblocking(fds[1])  # bridge end is non-blocking for the read/write threads
  setSocketBufferSize(fds[0], 512 * 1024)  # 512KB buffers
  setSocketBufferSize(fds[1], 512 * 1024)
  result.asyncFd = fds[0]
  result.bridgeFd = fds[1]

  if cfg.tunFd >= 0:
    result.tunFd = cfg.tunFd
    result.ifName = if cfg.name.len > 0: cfg.name else: "vpn"
    result.opened = true
    return

  # Allocate the interface, trying alternate names on conflict.
  var fd = cint(-1)
  var actual = ""
  var lastErr = cint(0)
  for name in candidateNames(cfg.name):
    let (f, a, e) = openTunFd(name)
    lastErr = e
    if f >= 0:
      fd = f; actual = a; break
    if e != EBUSY:
      break # Only retry on a name conflict.

  if fd < 0:
    discard close(result.asyncFd); discard close(result.bridgeFd)
    result.asyncFd = cint(-1); result.bridgeFd = cint(-1)
    raise newException(OSError, "TUNSETIFF failed: " & $strerror(lastErr))

  result.tunFd = fd
  result.ifName = actual
  result.opened = true

proc shellQuote(s: string): string =
  result = "'"
  for c in s:
    if c == '\'': result.add "'\\''"
    else: result.add c
  result.add "'"

proc ipCmd(args: string): int =
  execShellCmd("ip " & args & " 2>/dev/null")

proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) =
  ## Bring the interface up with the given MTU and Yggdrasil address.
  ## Assign only the node address as /128.  The 200::/7 network belongs in the
  ## route table; putting /7 on the address creates an implicit kernel route
  ## without the required preferred source and breaks return-path selection.
  if not tun.opened: return
  let name = shellQuote(tun.ifName)
  discard ipCmd("link set dev " & name & " mtu " & $mtu)
  if ipv6.len > 0:
    discard ipCmd("-6 address replace " & shellQuote(ipv6 & "/128") & " dev " & name)
  discard ipCmd("link set dev " & name & " up")

proc configureRoutes*(tun: TunAdapter) =
  ## Route the whole Yggdrasil 200::/7 range through the TUN interface with the
  ## node address as preferred source, equivalent to:
  ##   ip -6 route replace 200::/7 dev ygg0 src <nim-ygg-address>
  if not tun.opened: return
  let name = shellQuote(tun.ifName)
  var src = tun.cfg.ipv6
  if src.contains("/"):
    src = src.split('/')[0]
  if src.len > 0:
    discard ipCmd("-6 route replace " & YggPrefix & " dev " & name & " src " & shellQuote(src))
  else:
    discard ipCmd("-6 route replace " & YggPrefix & " dev " & name)

proc startIo*(tun: TunAdapter) =
  ## Start the background I/O threads and the Chronos transport. Must be called
  ## once after openTun()/configureInterface() for any data to flow.
  if not tun.opened: return
  if tun.running: return
  tun.running = true
  setNonblocking(tun.asyncFd)
  tun.transport = fromPipe(AsyncFD(tun.asyncFd))
  createThread(tun.readThread, tunReadThread, tun)
  createThread(tun.writeThread, tunWriteThread, tun)

proc close*(tun: TunAdapter) =
  tun.running = false
  # Wake / close the bridge so the threads see EOF and exit.
  if tun.bridgeFd >= 0:
    discard posix.shutdown(SocketHandle(tun.bridgeFd), SHUT_RDWR)
    discard close(tun.bridgeFd)
    tun.bridgeFd = cint(-1)
  if tun.tunFd >= 0:
    discard close(tun.tunFd)
    tun.tunFd = cint(-1)
  # transport is left for the dispatcher; it will hit EOF and close itself.
  tun.opened = false

# ── Async TUN I/O via the bridge transport ──────────────────────────────────

proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
  ## Read one packet from the TUN device.
  if tun.transport == nil:
    raise newException(IOError, "TUN transport not started (call startIo)")
  var hdr: array[4, byte]
  await tun.transport.readExactly(addr hdr[0], 4)
  let m = int((uint32(hdr[0]) shl 24) or (uint32(hdr[1]) shl 16) or
              (uint32(hdr[2]) shl 8) or uint32(hdr[3]))
  if m <= 0 or m > TUN_MAX_PACKET:
    return newSeq[byte](0)
  result = newSeq[byte](m)
  await tun.transport.readExactly(addr result[0], m)

proc writePacket*(tun: TunAdapter, packet: seq[byte]): Future[void] {.async.} =
  ## Write one packet to the TUN device.
  if tun.transport == nil:
    raise newException(IOError, "TUN transport not started (call startIo)")
  let m = packet.len
  var hdr: array[4, byte]
  hdr[0] = byte((m shr 24) and 0xff)
  hdr[1] = byte((m shr 16) and 0xff)
  hdr[2] = byte((m shr 8) and 0xff)
  hdr[3] = byte(m and 0xff)
  discard await tun.transport.write(addr hdr[0], 4)
  if m > 0:
    discard await tun.transport.write(unsafeAddr packet[0], m)

# ── Packet classification ───────────────────────────────────────────────────

proc detectInnerProtocol*(packet: openArray[byte]): InnerProtocol =
  if packet.len == 0: return ipOther
  let version = packet[0] shr 4
  if version == 4:
    if packet.len < 20: return ipOther
    case packet[9]
    of 6: ipTcp
    of 17: ipUdp
    of 1: ipIcmp
    else: ipOther
  elif version == 6:
    if packet.len < 40: return ipOther
    case packet[6]
    of 6: ipTcp
    of 17: ipUdp
    of 58: ipIcmp
    else: ipOther
  else:
    ipOther

# ── IPv4-in-IPv6 encapsulation ──────────────────────────────────────────────

proc encapsulate4in6*(src, dst: IPv6Address, ipv4: openArray[byte]): seq[byte] =
  ## Wrap an IPv4 packet inside an IPv6 packet with the given src/dst addresses.
  ## The next-header is set to 4 (IPv4 encapsulation).
  result = newSeq[byte](40 + ipv4.len)
  # IPv6 header
  result[0] = 0x60'u8  # version 6
  result[6] = 4'u8     # next header = IPv4-in-IPv6
  result[4] = byte((ipv4.len shr 8) and 0xff)
  result[5] = byte(ipv4.len and 0xff)
  for i in 0 ..< 16: result[8 + i] = src[i]
  for i in 0 ..< 16: result[24 + i] = dst[i]
  for i in 0 ..< ipv4.len: result[40 + i] = ipv4[i]

proc decapsulate4in6*(packet: openArray[byte]): Option[seq[byte]] =
  ## Extract the inner IPv4 packet from an IPv4-in-IPv6 encapsulated packet.
  if packet.len < 40: return none(seq[byte])
  let version = packet[0] shr 4
  if version != 6: return none(seq[byte])
  if packet[6] != 4'u8: return none(seq[byte])
  let inner = packet[40 ..< packet.len]
  return some(inner)

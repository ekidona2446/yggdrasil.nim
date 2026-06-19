## TUN adapter — macOS utun implementation.
##
## Creates a macOS utun interface (e.g. utun0), assigns the Yggdrasil IPv6
## address, and bridges packet I/O between the kernel interface and Chronos.
##
## Employs an AF_UNIX socketpair bridge identical to Linux for async Chronos I/O.

import std/[os, strutils, posix, options]
import chronos
import chronos/transports/stream
import ../core/types
import ../util/ipnet

when not defined(macosx):
  {.error: "tun_macos.nim is macOS-only".}

const
  PF_SYSTEM = 32.cint
  SYSPROTO_CONTROL = 2.cint
  AF_SYS_CONTROL = 2.uint8
  CTLIOCGINFO = 0xc0644e03.culong
  UTUN_OPT_IFNAME = 2.cint
  TUN_MAX_PACKET = 65535 + 14
  YggPrefix* = "200::/7"

type
  CtlInfo = object
    ctl_id: uint32
    ctl_name: array[96, char]

  SockAddrCtl = object
    sc_len: uint8
    sc_family: uint8
    ss_sysaddr: uint16
    sc_id: uint32
    sc_unit: uint32
    sc_reserved: array[5, uint32]

  TunPlatform* = enum tpMacOS

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
    asyncFd*: cint
    bridgeFd*: cint
    transport*: StreamTransport

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
  var off = 0
  while off < n:
    let w = posix.write(fd, cast[pointer](cast[uint](data) + uint(off)), n - off)
    if w > 0: off += int(w)
    elif w == 0: return false
    else:
      if errno == EINTR: continue
      return false
  true

proc tryWriteNonblocking(fd: cint, data: pointer, n: int): bool =
  var off = 0
  while off < n:
    let w = posix.write(fd, cast[pointer](cast[uint](data) + uint(off)), n - off)
    if w > 0: off += int(w)
    elif w == 0: return false
    else:
      if errno == EINTR: continue
      if errno == EAGAIN or errno == EWOULDBLOCK: return false
      return false
  true

proc readAll(fd: cint, data: pointer, n: int): bool =
  var off = 0
  while off < n:
    let r = posix.read(fd, cast[pointer](cast[ByteAddress](data) + ByteAddress(off)), n - off)
    if r > 0: off += r
    elif r == 0: return false
    else:
      if errno == EINTR: continue
      return false
  true

proc tunReadThread(tun: TunAdapter) {.thread.} =
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
      if tryWriteNonblocking(tun.bridgeFd, addr hdr[0], 4) and
         tryWriteNonblocking(tun.bridgeFd, addr buf[0], m): discard
    else:
      if not tun.running: break
      if errno == EINTR: continue
      discard posix.usleep(1000)

proc tunWriteThread(tun: TunAdapter) {.thread.} =
  var hdr: array[4, byte]
  var buf = newString(TUN_MAX_PACKET)
  while tun.running:
    if not readAll(tun.bridgeFd, addr hdr[0], 4): break
    let m = int((uint32(hdr[0]) shl 24) or (uint32(hdr[1]) shl 16) or
                (uint32(hdr[2]) shl 8) or uint32(hdr[3]))
    if m <= 0 or m > buf.len: continue
    if not readAll(tun.bridgeFd, addr buf[0], m): break
    if not writeAll(tun.tunFd, addr buf[0], m):
      if not tun.running: break
      discard posix.usleep(1000)

proc openUtunFd(unit: int): tuple[fd: cint, actual: string, err: cint] =
  let fd = posix.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
  if fd < 0: return (cint(-1), "", errno)
  var info: CtlInfo
  zeroMem(addr info, sizeof(info))
  let name = "com.apple.net.utun_control"
  for i in 0 ..< min(name.len, sizeof(info.ctl_name) - 1):
    info.ctl_name[i] = name[i]
  if ioctl(fd, CTLIOCGINFO, addr info) < 0:
    let e = errno; discard close(fd); return (cint(-1), "", e)
  var addrCtl: SockAddrCtl
  zeroMem(addr addrCtl, sizeof(addrCtl))
  addrCtl.sc_len = sizeof(addrCtl).uint8
  addrCtl.sc_family = AF_SYSTEM.uint8
  addrCtl.ss_sysaddr = AF_SYS_CONTROL.uint16
  addrCtl.sc_id = info.ctl_id
  addrCtl.sc_unit = (unit + 1).uint32
  if posix.connect(SocketHandle(fd), cast[ptr SockAddr](addr addrCtl), sizeof(addrCtl).SockLen) < 0:
    let e = errno; discard close(fd); return (cint(-1), "", e)
  var ifname: array[64, char]
  var iflen = sizeof(ifname).SockLen
  if posix.getsockopt(SocketHandle(fd), SYSPROTO_CONTROL, UTUN_OPT_IFNAME, addr ifname[0], iflen) < 0:
    let e = errno; discard close(fd); return (cint(-1), "", e)
  var actual = ""
  for c in ifname:
    if c == '\0': break
    actual.add c
  (fd, actual, 0.cint)

proc openTun*(cfg: TunConfig): TunAdapter =
  result = TunAdapter(
    cfg: cfg, platform: tpMacOS, opened: false,
    tunFd: cint(-1), running: false,
    asyncFd: cint(-1), bridgeFd: cint(-1),
  )
  if not cfg.enable: return
  if cfg.tunFd >= 0:
    result.tunFd = cfg.tunFd
    result.ifName = if cfg.name.len > 0: cfg.name else: "utun0"
    result.opened = true
    return
  var fds: array[2, cint]
  if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
    raise newException(OSError, "TUN socketpair failed: " & $strerror(errno))
  setCloexec(fds[0]); setCloexec(fds[1])
  setNonblocking(fds[1])
  setSocketBufferSize(fds[0], 512 * 1024)
  setSocketBufferSize(fds[1], 512 * 1024)
  result.asyncFd = fds[0]
  result.bridgeFd = fds[1]
  var fd = cint(-1); var actual = ""; var lastErr = cint(0)
  for unit in 0 .. 10:
    let (f, a, e) = openUtunFd(unit)
    lastErr = e
    if f >= 0: fd = f; actual = a; break
  if fd < 0:
    discard close(result.asyncFd); discard close(result.bridgeFd)
    result.asyncFd = cint(-1); result.bridgeFd = cint(-1)
    raise newException(OSError, "openUtunFd failed: " & $strerror(lastErr))
  result.tunFd = fd; result.ifName = actual; result.opened = true

proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) =
  if not tun.opened: return
  let name = tun.ifName
  var cmds: seq[string]
  cmds.add("ifconfig " & name & " mtu " & $mtu)
  if ipv6.len > 0:
    cmds.add("ifconfig " & name & " inet6 " & ipv6 & " prefixlen 7 alias")
  cmds.add("ifconfig " & name & " up")
  for c in cmds: discard execShellCmd(c & " 2>/dev/null")

proc configureRoutes*(tun: TunAdapter) =
  if not tun.opened: return
  let name = tun.ifName
  discard execShellCmd("route add -inet6 " & YggPrefix & " -interface " & name & " 2>/dev/null")

proc startIo*(tun: TunAdapter) =
  if not tun.opened or tun.running: return
  tun.running = true
  setNonblocking(tun.asyncFd)
  tun.transport = fromPipe(AsyncFD(tun.asyncFd))
  createThread(tun.readThread, tunReadThread, tun)
  createThread(tun.writeThread, tunWriteThread, tun)

proc close*(tun: TunAdapter) =
  tun.running = false
  if tun.bridgeFd >= 0:
    discard posix.shutdown(SocketHandle(tun.bridgeFd), SHUT_RDWR)
    discard close(tun.bridgeFd); tun.bridgeFd = cint(-1)
  if tun.tunFd >= 0: discard close(tun.tunFd); tun.tunFd = cint(-1)
  tun.opened = false

proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
  if tun.transport == nil: raise newException(IOError, "TUN not started")
  var hdr: array[4, byte]
  await tun.transport.readExactly(addr hdr[0], 4)
  let m = int((uint32(hdr[0]) shl 24) or (uint32(hdr[1]) shl 16) or
              (uint32(hdr[2]) shl 8) or uint32(hdr[3]))
  if m <= 0 or m > TUN_MAX_PACKET: return newSeq[byte](0)
  result = newSeq[byte](m)
  await tun.transport.readExactly(addr result[0], m)

proc writePacket*(tun: TunAdapter, packet: seq[byte]): Future[void] {.async.} =
  if tun.transport == nil: raise newException(IOError, "TUN not started")
  let m = packet.len
  var hdr: array[4, byte]
  hdr[0] = byte((m shr 24) and 0xff); hdr[1] = byte((m shr 16) and 0xff)
  hdr[2] = byte((m shr 8) and 0xff); hdr[3] = byte(m and 0xff)
  discard await tun.transport.write(addr hdr[0], 4)
  if m > 0: discard await tun.transport.write(unsafeAddr packet[0], m)

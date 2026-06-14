## TUN adapter — Linux /dev/net/tun implementation.
##
## Creates a TUN interface, assigns the Yggdrasil IPv6 address.
## Uses background threads for I/O to avoid Chronos selector conflicts
## (TUN fd doesn't work with epoll in Chronos's expected way).
##
## Data plane wiring:
##   TUN read  → PacketConn.writeTo()  (incoming packets from OS → overlay)
##   PacketConn.readFrom() → TUN write (outgoing packets from overlay → OS)

import std/[os, strutils, options, posix, monotimes]
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

  TunAdapter* = ref object
    cfg*: TunConfig
    platform*: TunPlatform
    opened*: bool
    tunFd*: cint
    ifName*: string
    running*: bool
    readThread*: Thread[TunAdapter]
    writeThread*: Thread[TunAdapter]
    readChan*: AsyncQueue[seq[byte]]   ## packets read from TUN → Chronos
    writeChan*: Channel[seq[byte]]      ## packets from Chronos → TUN thread

# ── TUN background threads ──────────────────────────────────────────────────

proc tunReadThread(tun: TunAdapter) {.thread.} =
  ## Read packets from TUN fd and push to readChan via socketpair.
  var buf = newString(TUN_MAX_PACKET)
  while tun.running:
    let n = posix.read(tun.tunFd, addr buf[0], buf.len)
    if n <= 0:
      if not tun.running: break
      continue
    var packet = newSeq[byte](n)
    copyMem(addr packet[0], addr buf[0], n)
    try:
      tun.readChan.addLastNoWait(packet)
    except AsyncQueueFullError:
      discard  # drop packet if queue is full

proc tunWriteThread(tun: TunAdapter) {.thread.} =
  ## Read packets from writeChan and write to TUN fd.
  while tun.running:
    let (available, data) = tun.writeChan.tryRecv()
    if not available:
      discard posix.usleep(1000)  # 1ms
      continue
    if data.len == 0: continue
    var written = 0
    while written < data.len:
      let w = posix.write(tun.tunFd, unsafeAddr data[written], data.len - written)
      if w <= 0:
        break
      written += w

# ── TUN device management ───────────────────────────────────────────────────

proc openTun*(cfg: TunConfig): TunAdapter =
  ## Open a TUN device on Linux.
  result = TunAdapter(
    cfg: cfg,
    platform: tpLinux,
    opened: false,
    tunFd: -1,
    running: false,
    readChan: newAsyncQueue[seq[byte]](512),
  )
  result.writeChan.open(512)
  
  if not cfg.enable:
    return
  
  let fd = open("/dev/net/tun", O_RDWR)
  if fd < 0:
    let err = errno
    raise newException(OSError, "failed to open /dev/net/tun: " & $strerror(err))
  
  var req: TunIfReq
  let ifName = if cfg.name.len > 0: cfg.name else: "ygg0"
  for i in 0 ..< min(ifName.len, 15):
    req.ifr_name[i] = ifName[i]
  req.ifr_flags = uint16(IFF_TUN or IFF_NO_PI)
  
  if ioctl(fd, culong(TUNSETIFF), addr req) < 0:
    let err = errno
    discard close(fd)
    raise newException(OSError, "TUNSETIFF failed: " & $strerror(err))
  
  var actualName = ""
  for c in req.ifr_name:
    if c == '\0': break
    actualName.add c
  
  result.tunFd = fd
  result.ifName = actualName
  result.opened = true

proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) =
  if not tun.opened: return
  let name = tun.ifName
  discard execShellCmd("ip link set dev " & name & " mtu " & $mtu & " 2>/dev/null")
  if ipv6.len > 0:
    discard execShellCmd("ip address add " & ipv6 & "/7 dev " & name & " 2>/dev/null")
  discard execShellCmd("ip link set dev " & name & " up 2>/dev/null")

proc configureRoutes*(tun: TunAdapter) =
  let name = tun.ifName
  discard execShellCmd("ip -6 route add 200::/7 dev " & name & " 2>/dev/null")
  discard execShellCmd("ip -6 route replace 200::/7 dev " & name & " 2>/dev/null")

proc startIo*(tun: TunAdapter) =
  ## Start the background I/O threads.
  if not tun.opened: return
  tun.running = true
  createThread(tun.readThread, tunReadThread, tun)
  createThread(tun.writeThread, tunWriteThread, tun)

proc close*(tun: TunAdapter) =
  tun.running = false
  # Signal write thread to exit
  try: tun.writeChan.send(@[])
  except Exception: discard
  if tun.tunFd >= 0:
    discard close(tun.tunFd)
  tun.opened = false
  tun.tunFd = -1

# ── Async TUN I/O via channels ──────────────────────────────────────────────

proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
  ## Read a packet from the TUN device (via async queue).
  if not tun.opened: raise newException(IOError, "TUN not open")
  result = await tun.readChan.popFirst()

proc writePacket*(tun: TunAdapter, packet: seq[byte]): Future[void] {.async.} =
  ## Write a packet to the TUN device (via channel to write thread).
  if not tun.opened: raise newException(IOError, "TUN not open")
  try:
    tun.writeChan.send(packet)
  except Exception:
    discard

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

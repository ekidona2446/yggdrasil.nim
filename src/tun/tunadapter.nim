## TUN/utun/wintun boundary and packet classification.

import std/[options]
import ../core/types
import ../util/ipnet

type
  TunPlatform* = enum tpLinux, tpMacOS, tpWindows, tpUnsupported

  TunConfig* = object
    enable*: bool
    name*: string
    mtu*: int
    ipv6*: string
    ipv4*: string

  TunAdapter* = object
    cfg*: TunConfig
    platform*: TunPlatform
    opened*: bool
    fd*: int

  TunPacket* = object
    bytes*: seq[byte]
    innerProtocol*: InnerProtocol
    source*: Option[IpAddress]
    destination*: Option[IpAddress]

proc currentPlatform*(): TunPlatform =
  when defined(linux): tpLinux
  elif defined(macosx): tpMacOS
  elif defined(windows): tpWindows
  else: tpUnsupported

proc defaultTunConfig*(): TunConfig =
  TunConfig(enable: true, name: "ygg0", mtu: 65535, ipv6: "", ipv4: "")

proc initTunAdapter*(cfg = defaultTunConfig()): TunAdapter =
  TunAdapter(cfg: cfg, platform: currentPlatform(), opened: false, fd: -1)

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
    of 4: ipOther ## IPv4-over-IPv6 tunnel packet; inner parser handles payload.
    else: ipOther
  else:
    ipOther

proc parseTunPacket*(packet: openArray[byte]): TunPacket =
  result.bytes = newSeq[byte](packet.len)
  for i in 0 ..< packet.len: result.bytes[i] = packet[i]
  result.innerProtocol = detectInnerProtocol(packet)
  ## Source/destination extraction is intentionally conservative here. CKR code
  ## validates source addresses after decapsulation using util/ipnet parsers.

proc encapsulate4in6*(src, dst: IPv6Address, ipv4Packet: openArray[byte],
                      hopLimit: byte = 64): seq[byte] =
  ## RFC 2473-style IPv4 packet encapsulated in an IPv6 packet with Next Header=4.
  if ipv4Packet.len > 65535:
    raise newException(ValueError, "IPv4 payload too large for IPv6 payload length")
  result = newSeq[byte](40 + ipv4Packet.len)
  result[0] = 0x60'u8
  result[4] = byte((ipv4Packet.len shr 8) and 0xff)
  result[5] = byte(ipv4Packet.len and 0xff)
  result[6] = 4'u8
  result[7] = hopLimit
  for i in 0 ..< 16:
    result[8 + i] = src[i]
    result[24 + i] = dst[i]
  for i in 0 ..< ipv4Packet.len:
    result[40 + i] = ipv4Packet[i]

proc decapsulate4in6*(packet: openArray[byte]): Option[seq[byte]] =
  if packet.len < 40: return none(seq[byte])
  if packet[0] shr 4 != 6 or packet[6] != 4'u8: return none(seq[byte])
  let plen = (int(packet[4]) shl 8) or int(packet[5])
  if packet.len < 40 + plen: return none(seq[byte])
  var payload = newSeq[byte](plen)
  for i in 0 ..< plen:
    payload[i] = packet[40 + i]
  result = some(payload)

proc open*(t: var TunAdapter) =
  if not t.cfg.enable: return
  if t.cfg.mtu < 1280 or t.cfg.mtu > 65535:
    raise newException(ValueError, "invalid TUN MTU")
  case t.platform
  of tpLinux:
    ## Production: open /dev/net/tun and issue TUNSETIFF, then configure routes.
    t.opened = true
    t.fd = -1
  of tpMacOS:
    ## Production: utun control socket.
    t.opened = true
    t.fd = -1
  of tpWindows:
    ## Production: Wintun FFI.
    t.opened = true
    t.fd = -1
  of tpUnsupported:
    raise newException(OSError, "TUN unsupported on this platform")

proc close*(t: var TunAdapter) =
  t.opened = false
  t.fd = -1

proc readPacket*(t: TunAdapter): Option[TunPacket] =
  if not t.opened: return none(TunPacket)
  ## Production: blocking/async read from fd/driver.
  none(TunPacket)

proc writePacket*(t: TunAdapter, packet: openArray[byte]) =
  if not t.opened: raise newException(IOError, "TUN is not open")
  discard packet

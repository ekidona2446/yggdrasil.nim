## Shared protocol types.

import std/[hashes, strutils, sequtils]
import ../util/bytes

export Bytes32, Bytes16, toHex, fromHex, bytes32FromHex

type
  NodeId* = object
    ## Public-key identity digest/public key. In production this is Ed25519 or a
    ## hybrid certificate public identity.
    bytes*: Bytes32

  Coordinates* = seq[uint64]

  IPv6Address* = Bytes16

  InnerProtocol* = enum
    ipAny, ipTcp, ipUdp, ipIcmp, ipOther

  TransportKind* = enum
    tkTcp, tkTls, tkQuic, tkWebSocket, tkUnix, tkUdp, tkSocks, tkSocksTls

  PeerUri* = object
    scheme*: string
    host*: string
    port*: int
    path*: string
    kind*: TransportKind
    ## Query parameters
    pinnedKeys*: seq[string]   ## ?key=hex — Ed25519 public keys to pin
    sni*: string               ## ?sni=domain — custom TLS SNI
    priority*: uint8           ## ?priority=N
    password*: string          ## ?password=string
    maxBackoff*: int           ## ?maxbackoff=seconds

proc `==`*(a, b: NodeId): bool = a.bytes == b.bytes

proc hash*(id: NodeId): Hash =
  var h: Hash = 0
  for b in id.bytes:
    h = h !& hash(int(b))
  result = !$h

proc nodeIdFromHex*(s: string): NodeId = NodeId(bytes: bytes32FromHex(s))

proc toHex*(id: NodeId): string = toHex(id.bytes)

proc short*(id: NodeId): string =
  const Digits = "0123456789abcdef"
  result = ""
  for i in 0 ..< 6:
    result.add Digits[int((id.bytes[i] shr 4) and 0x0f)]
    result.add Digits[int(id.bytes[i] and 0x0f)]

proc `$`*(id: NodeId): string = toHex(id)

proc cmpNodeId*(a, b: NodeId): int =
  for i in 0 ..< 32:
    if a.bytes[i] < b.bytes[i]: return -1
    if a.bytes[i] > b.bytes[i]: return 1
  return 0

proc xorDistance*(a, b: NodeId): Bytes32 =
  for i in 0 ..< 32:
    result[i] = a.bytes[i] xor b.bytes[i]

proc cmpDistance*(a, b: Bytes32): int =
  ## Distances are compared big-endian as in Kademlia.
  for i in 0 ..< 32:
    if a[i] < b[i]: return -1
    if a[i] > b[i]: return 1
  return 0

proc coordToString*(c: Coordinates): string =
  if c.len == 0: return "/"
  result = c.mapIt($it).join(".")

proc parseCoordinates*(s: string): Coordinates =
  let clean = s.strip()
  if clean.len == 0 or clean == "/": return @[]
  for part in clean.split('.'):
    result.add parseUInt(part).uint64

proc commonPrefixLen*(a, b: Coordinates): int =
  let n = min(a.len, b.len)
  for i in 0 ..< n:
    if a[i] != b[i]: return i
  result = n

proc treeDistance*(a, b: Coordinates): uint64 =
  ## Distance on a tree: climb from a to LCA, descend to b.
  let c = commonPrefixLen(a, b)
  result = uint64((a.len - c) + (b.len - c))

proc hexU16(g: uint16): string =
  const Digits = "0123456789abcdef"
  if g == 0'u16: return "0"
  var x = g
  var tmp: array[4, char]
  var pos = 4
  while x != 0'u16:
    dec pos
    tmp[pos] = Digits[int(x and 0x0f'u16)]
    x = x shr 4
  result = ""
  for i in pos ..< 4: result.add tmp[i]

proc toIPv6String*(ip6: IPv6Address): string =
  ## Simple non-compressing IPv6 stringifier, deterministic for tests/admin.
  var groups: array[8, uint16]
  for i in 0 ..< 8:
    groups[i] = (uint16(ip6[i * 2]) shl 8) or uint16(ip6[i * 2 + 1])
  var parts: seq[string]
  for g in groups:
    parts.add hexU16(g)
  result = parts.join(":")

proc deriveYggAddress*(id: NodeId): IPv6Address =
  ## Yggdrasil-compatible address.AddrForKey derivation.
  ##
  ## Public Yggdrasil uses the 200::/7 range, not ULA. The address begins with
  ## prefix byte 0x02. The next byte stores the count of leading 1 bits in the
  ## bitwise inverse of the Ed25519 public key, then the remaining inverted key
  ## bits are packed into the rest of the IPv6 address.
  var inv: array[32, byte]
  for i in 0 ..< 32: inv[i] = not id.bytes[i]
  var temp: seq[byte]
  var done = false
  var ones: byte = 0
  var bits: byte = 0
  var nBits = 0
  for idx in 0 ..< 256:
    let bit = (inv[idx div 8] and (0x80'u8 shr (idx mod 8))) shr (7 - (idx mod 8))
    if not done and bit != 0:
      inc ones
      continue
    if not done and bit == 0:
      done = true
      continue
    bits = (bits shl 1) or bit
    inc nBits
    if nBits == 8:
      nBits = 0
      temp.add bits
      bits = 0
  result[0] = 0x02'u8
  result[1] = ones
  for i in 0 ..< min(14, temp.len): result[2 + i] = temp[i]

proc keyPrefixForYggAddress*(address: IPv6Address): NodeId =
  ## Yggdrasil-compatible address.Address.GetKey partial-key derivation.
  let ones = int(address[1])
  for idx in 0 ..< ones:
    result.bytes[idx div 8] = result.bytes[idx div 8] or (0x80'u8 shr (idx mod 8))
  let keyOffset = ones + 1
  let addrOffset = 16
  for idx in addrOffset ..< 8 * 16:
    var bits = address[idx div 8] and (0x80'u8 shr (idx mod 8))
    bits = bits shl (idx mod 8)
    let keyIdx = keyOffset + (idx - addrOffset)
    bits = bits shr (keyIdx mod 8)
    let keyByte = keyIdx div 8
    if keyByte >= 32: break
    result.bytes[keyByte] = result.bytes[keyByte] or bits
  for i in 0 ..< 32: result.bytes[i] = not result.bytes[i]

proc deriveULA*(id: NodeId): IPv6Address =
  ## Backwards-compatible name retained for old call sites. Returns the public
  ## Yggdrasil 200::/7 address, not a ULA.
  deriveYggAddress(id)

# ── Subnet / Bloom-transform derivation ──────────────────────────────────────
#
# Go's Ironwood uses WithBloomTransform(SubnetForKey(key).GetKey()).  This
# converts a full 32-byte Ed25519 public key into a coarse partial key derived
# from its /64 Yggdrasil subnet, so that bloom-filter lookups performed with an
# address-derived partial key match bloom entries populated with full keys.

type YggSubnet* = array[8, byte]

proc deriveYggSubnet*(id: NodeId): YggSubnet =
  ## Yggdrasil-compatible address.SubnetForKey derivation.
  ## Same as AddrForKey but truncated to 8 bytes and with the subnet bit set.
  let yggAddr = deriveYggAddress(id)
  for i in 0 ..< 8: result[i] = yggAddr[i]
  result[0] = result[0] or 0x01'u8  # mark as subnet (prefix 0x02 | 0x01 = 0x03)

proc subnetGetKey*(snet: YggSubnet): NodeId =
  ## Yggdrasil-compatible Subnet.GetKey derivation.
  ## Mirrors Address.GetKey but operates on the 8-byte subnet, recovering only
  ## the ~56 bits encoded in a /64 prefix.  Unknown bits end up as 0xFF after
  ## inversion, matching Go's behaviour.
  let ones = int(snet[1])
  for idx in 0 ..< ones:
    result.bytes[idx div 8] = result.bytes[idx div 8] or (0x80'u8 shr (idx mod 8))
  let keyOffset = ones + 1
  let addrOffset = 16  # 8 * len(prefix) + 8 = 8*1 + 8
  for idx in addrOffset ..< 8 * 8:  # 8 * len(subnet) = 64
    var bits = snet[idx div 8] and (0x80'u8 shr (idx mod 8))
    bits = bits shl (idx mod 8)
    let keyIdx = keyOffset + (idx - addrOffset)
    bits = bits shr (keyIdx mod 8)
    let keyByte = keyIdx div 8
    if keyByte >= 32: break
    result.bytes[keyByte] = result.bytes[keyByte] or bits
  for i in 0 ..< 32: result.bytes[i] = not result.bytes[i]

proc bloomTransform*(key: NodeId): NodeId =
  ## Transform applied to keys before bloom-filter operations.
  ## Equivalent to Go's WithBloomTransform(SubnetForKey(key).GetKey()).
  subnetGetKey(deriveYggSubnet(key))

proc transportKind*(scheme: string): TransportKind =
  case scheme.toLowerAscii()
  of "tcp": tkTcp
  of "tcp+tls", "tls": tkTls
  of "quic", "h3", "http3": tkQuic
  of "ws", "wss", "websocket": tkWebSocket
  of "unix", "unixs": tkUnix
  of "udp": tkUdp
  of "socks": tkSocks
  of "sockstls": tkSocksTls
  else: raise newException(ValueError, "unsupported peer scheme: " & scheme)

proc isStreamTransport*(k: TransportKind): bool =
  k in {tkTcp, tkTls, tkWebSocket, tkUnix, tkSocks, tkSocksTls}

## Shared protocol types.

import std/[hashes, strutils, sequtils]
import ../util/bytes

export Bytes32, Bytes16, toHex, fromHex, bytes32FromHex

type
  NodeId* = object
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
    pinnedKeys*: seq[string]
    sni*: string
    priority*: uint8
    password*: string
    maxBackoff*: int

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

proc xorDistance*(a, b: NodeId): Bytes32 =
  for i in 0 ..< 32: result[i] = a.bytes[i] xor b.bytes[i]

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
  var groups: array[8, uint16]
  for i in 0 ..< 8:
    groups[i] = (uint16(ip6[i * 2]) shl 8) or uint16(ip6[i * 2 + 1])
  var parts: seq[string]
  for g in groups:
    parts.add hexU16(g)
  result = parts.join(":")

proc deriveYggAddress*(id: NodeId): IPv6Address =
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
  let ones = int(address[1])
  for idx in 0 ..< ones:
    result.bytes[idx div 8] = result.bytes[idx div 8] or (0x80'u8 shr (idx mod 8))
  let keyOffset = ones + 1
  let addrOffset = 16  # 8 * 1 + 8
  
  for idx in addrOffset ..< 8 * 16:
    let addrByte = address[idx div 8]
    let bitPosInAddr = idx mod 8
    let mask = byte(0x80'u8 shr bitPosInAddr)
    var bitVal = (addrByte and mask) shr (7 - bitPosInAddr)
    
    let keyIdx = keyOffset + (idx - addrOffset)
    let keyByte = keyIdx div 8
    let bitPosInKey = keyIdx mod 8
    
    if keyByte >= 32: break
    result.bytes[keyByte] = result.bytes[keyByte] or (byte(bitVal) shl bitPosInKey)
  
  for i in 0 ..< 32:
    result.bytes[i] = not result.bytes[i]

proc deriveULA*(id: NodeId): IPv6Address =
  deriveYggAddress(id)

type YggSubnet* = array[8, byte]

proc toSubnetString*(snet: YggSubnet): string =
  ## Returns subnet as IPv6 prefix string (e.g., "300:2:68:94::/64")
  ## YggSubnet is array[8, byte] where each byte is a hex group
  const HexDigits = "0123456789abcdef"
  proc byteToHex(b: byte): string =
    result = newString(2)
    result[0] = HexDigits[int((b shr 4) and 0x0f)]
    result[1] = HexDigits[int(b and 0x0f)]
  result = snet[0].byteToHex & ":" & snet[1].byteToHex & ":" & 
          snet[2].byteToHex & ":" & snet[3].byteToHex & "::/64"

proc deriveYggSubnet*(id: NodeId): YggSubnet =
  let yggAddr = deriveYggAddress(id)
  for i in 0 ..< 8: result[i] = yggAddr[i]
  result[0] = result[0] or 0x01'u8  # mark as subnet (0x02 | 0x01 = 0x03)

proc subnetGetKey*(snet: YggSubnet): NodeId =
  let ones = int(snet[1])
  for idx in 0 ..< ones:
    result.bytes[idx div 8] = result.bytes[idx div 8] or (0x80'u8 shr (idx mod 8))
  let keyOffset = ones + 1
  let addrOffset = 16
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

proc cmpNodeId*(a, b: NodeId): int =
  for i in 0 ..< 32:
    if a.bytes[i] < b.bytes[i]: return -1
    if a.bytes[i] > b.bytes[i]: return 1
  return 0

proc cmpDistance*(a, b: Bytes32): int =
  ## Distances are compared big-endian as in Kademlia.
  for i in 0 ..< 32:
    if a[i] < b[i]: return -1
    if a[i] > b[i]: return 1
  return 0

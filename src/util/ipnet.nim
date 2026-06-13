## Small IPv4/IPv6 CIDR parser and matcher for CKR/DNS tests.

import std/strutils

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

type
  IpFamily* = enum ifIPv4, ifIPv6

  IpAddress* = object
    family*: IpFamily
    bytes*: array[16, byte] ## IPv4 uses bytes[0..3].

  IpNet* = object
    family*: IpFamily
    address*: IpAddress
    prefixLen*: int
    raw*: string

proc parseIPv4Bytes(s: string): array[4, byte] =
  let parts = s.strip().split('.')
  if parts.len != 4:
    raise newException(ValueError, "invalid IPv4 address: " & s)
  for i, p in parts:
    if p.len == 0: raise newException(ValueError, "invalid IPv4 address: " & s)
    let v = parseInt(p)
    if v < 0 or v > 255: raise newException(ValueError, "invalid IPv4 octet: " & p)
    result[i] = byte(v)

proc parseHextetPart(part: string): seq[uint16] =
  if part.len == 0: return @[]
  for token in part.split(':'):
    if token.len == 0: raise newException(ValueError, "empty IPv6 hextet")
    if token.contains('.'):
      let v4 = parseIPv4Bytes(token)
      result.add (uint16(v4[0]) shl 8) or uint16(v4[1])
      result.add (uint16(v4[2]) shl 8) or uint16(v4[3])
    else:
      if token.len > 4: raise newException(ValueError, "IPv6 hextet too long: " & token)
      var v = 0
      for c in token.toLowerAscii():
        v = v shl 4
        if c >= '0' and c <= '9': v += ord(c) - ord('0')
        elif c >= 'a' and c <= 'f': v += 10 + ord(c) - ord('a')
        else: raise newException(ValueError, "invalid IPv6 hextet: " & token)
      result.add uint16(v)

proc parseIPv6Bytes(s0: string): array[16, byte] =
  var s = s0.strip()
  let pct = s.find('%')
  if pct >= 0: s = s[0 ..< pct]
  if s.len == 0: raise newException(ValueError, "empty IPv6 address")

  var groups: seq[uint16]
  let dc = s.find("::")
  if dc >= 0:
    if s.find("::", dc + 2) >= 0:
      raise newException(ValueError, "IPv6 address contains multiple ::")
    let leftStr = if dc == 0: "" else: s[0 ..< dc]
    let rightStr = if dc + 2 >= s.len: "" else: s[dc + 2 .. ^1]
    let left = parseHextetPart(leftStr)
    let right = parseHextetPart(rightStr)
    let zeros = 8 - left.len - right.len
    if zeros < 1: raise newException(ValueError, "IPv6 :: expands to no groups")
    groups = left
    for _ in 0 ..< zeros: groups.add 0'u16
    groups.add right
  else:
    groups = parseHextetPart(s)
    if groups.len != 8: raise newException(ValueError, "IPv6 address must contain 8 groups without ::")

  if groups.len != 8: raise newException(ValueError, "invalid IPv6 group count")
  for i, g in groups:
    result[i * 2] = byte((g shr 8) and 0xff)
    result[i * 2 + 1] = byte(g and 0xff)

proc parseIpAddress*(s: string): IpAddress =
  if s.contains(':'):
    result.family = ifIPv6
    result.bytes = parseIPv6Bytes(s)
  else:
    result.family = ifIPv4
    let v4 = parseIPv4Bytes(s)
    for i in 0 ..< 4: result.bytes[i] = v4[i]

proc parseIpNet*(s: string): IpNet =
  let clean = s.strip()
  if clean.len == 0: raise newException(ValueError, "empty IP network")
  let parts = clean.split('/')
  if parts.len > 2: raise newException(ValueError, "invalid CIDR: " & s)
  result.address = parseIpAddress(parts[0])
  result.family = result.address.family
  result.prefixLen = if result.family == ifIPv4: 32 else: 128
  if parts.len == 2:
    result.prefixLen = parseInt(parts[1])
  let maxPrefix = if result.family == ifIPv4: 32 else: 128
  if result.prefixLen < 0 or result.prefixLen > maxPrefix:
    raise newException(ValueError, "invalid prefix length: " & $result.prefixLen)
  result.raw = clean

proc contains*(net: IpNet, ip: IpAddress): bool =
  if net.family != ip.family: return false
  var bits = net.prefixLen
  let bytesToCheck = if net.family == ifIPv4: 4 else: 16
  for i in 0 ..< bytesToCheck:
    if bits <= 0: return true
    let maskBits = min(bits, 8)
    let mask = byte((0xff'u16 shl (8 - maskBits)) and 0xff)
    if (net.address.bytes[i] and mask) != (ip.bytes[i] and mask): return false
    bits -= maskBits
  result = true

proc contains*(net: IpNet, ip: string): bool = net.contains(parseIpAddress(ip))

proc `$`*(ip: IpAddress): string =
  if ip.family == ifIPv4:
    result = @[$ip.bytes[0], $ip.bytes[1], $ip.bytes[2], $ip.bytes[3]].join(".")
  else:
    var parts: seq[string]
    for i in 0 ..< 8:
      let g = (uint16(ip.bytes[i * 2]) shl 8) or uint16(ip.bytes[i * 2 + 1])
      parts.add hexU16(g)
    result = parts.join(":")

proc `$`*(net: IpNet): string = net.raw

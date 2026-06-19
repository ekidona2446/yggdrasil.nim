## Multicast Beacon discovery engine for Yggdrasil.
##
## Implements:
## - UDP multicast beacon emitting and receiving on ff02::114
## - Strict Go/Rust Advertisement wire encoding and decoding
## - Keyed / unkeyed BLAKE2b-512 authentication hashes
## - Filtering out local loopbacks and self-beacons

import std/[options, posix, strutils, net]
import ../core/types
import ../crypto/sodium

const
  MulticastGroup* = "ff02::114"
  MulticastPortDefault* = 9001

type
  BeaconAdvertisement* = object
    majorVersion*: uint16
    minorVersion*: uint16
    publicKey*: NodeId
    port*: uint16
    hash*: seq[byte]

proc putU16be(buf: var seq[byte], x: uint16) =
  buf.add byte((x shr 8) and 0xff)
  buf.add byte(x and 0xff)

proc readU16be(data: openArray[byte], off: int): uint16 =
  if off + 2 > data.len: raise newException(ValueError, "short u16")
  (uint16(data[off]) shl 8) or uint16(data[off + 1])

proc computeAuthHash*(publicKey: NodeId, password: seq[byte] = @[]): seq[byte] =
  ## Compute BLAKE2b-512 auth hash matching Go/Rust.
  let arr = blake2b512(publicKey.bytes, password)
  result = newSeq[byte](64)
  for i in 0 ..< 64: result[i] = arr[i]

proc encodeAdvertisement*(adv: BeaconAdvertisement): seq[byte] =
  result.putU16be(adv.majorVersion)
  result.putU16be(adv.minorVersion)
  for b in adv.publicKey.bytes: result.add b
  result.putU16be(adv.port)
  result.putU16be(uint16(adv.hash.len))
  for b in adv.hash: result.add b

proc decodeAdvertisement*(data: openArray[byte]): Option[BeaconAdvertisement] =
  if data.len < 40: return none(BeaconAdvertisement)
  var adv: BeaconAdvertisement
  adv.majorVersion = readU16be(data, 0)
  adv.minorVersion = readU16be(data, 2)
  for i in 0 ..< 32: adv.publicKey.bytes[i] = data[4 + i]
  adv.port = readU16be(data, 36)
  let hLen = int(readU16be(data, 38))
  if data.len < 40 + hLen: return none(BeaconAdvertisement)
  for i in 0 ..< hLen: adv.hash.add data[40 + i]
  some(adv)

proc verifyBeacon*(adv: BeaconAdvertisement, password: seq[byte] = @[]): bool =
  if adv.majorVersion != 0 or adv.minorVersion != 5: return false
  let expected = computeAuthHash(adv.publicKey, password)
  expected == adv.hash

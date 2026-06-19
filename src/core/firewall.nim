## Comprehensive standalone firewall logic for Yggdrasil overlay.
##
## Implements:
## 1. Peering connection filtering (AllowedPublicKeys, BlockedPublicKeys).
## 2. GroupPassword domain partitioning (folded into Session signature preimages).
## 3. AllowedOpenPorts incoming delivery filtration.

import std/[strutils, sequtils]
import ../config/configuration
import ../core/types
import ../crypto/sodium
import ../util/bytes

proc extractDestinationPort*(packet: openArray[byte]): int =
  ## Parse IP packet (IPv4 or IPv6) and extract TCP/UDP destination port.
  if packet.len < 20: return 0
  let ver = packet[0] shr 4
  if ver == 4:
    let ihl = int(packet[0] and 0x0f'u8)
    let hLen = ihl * 4
    if packet.len < hLen + 4: return 0
    let proto = packet[9]
    if proto in [6'u8, 17]:
      return int((uint16(packet[hLen + 2]) shl 8) or uint16(packet[hLen + 3]))
  elif ver == 6:
    if packet.len < 44: return 0
    let nxt = packet[6]
    if nxt in [6'u8, 17]:
      return int((uint16(packet[42]) shl 8) or uint16(packet[43]))
  return 0

proc checkPeeringFirewall*(fwCfg: FirewallConfig, peerKey: NodeId): bool =
  ## Check if an incoming or outgoing peering handshake is permitted.
  if not fwCfg.enable: return true
  let hexK = peerKey.toHex.toLowerAscii()
  if fwCfg.blockedPublicKeys.anyIt(it.toLowerAscii() == hexK):
    stderr.writeLine "[firewall] peering blocked by BlockedPublicKeys: " & hexK
    return false
  if fwCfg.allowedPublicKeys.len > 0 and not fwCfg.allowedPublicKeys.anyIt(it.toLowerAscii() == hexK):
    stderr.writeLine "[firewall] peering rejected (not listed in AllowedPublicKeys): " & hexK
    return false
  true

proc getGroupAuthPreimage*(fwCfg: FirewallConfig): seq[byte] =
  ## Derive the 32-byte signature preimage domain separator for GroupPassword.
  ## Exactly matches Go's `ironwood/encrypted` construction.
  if fwCfg.groupPassword == "":
    return @[]
  let prefix = "ironwood/encrypted\x00"
  var buf = newSeq[byte](prefix.len + fwCfg.groupPassword.len)
  for i in 0 ..< prefix.len: buf[i] = byte(prefix[i])
  for i in 0 ..< fwCfg.groupPassword.len: buf[prefix.len + i] = byte(fwCfg.groupPassword[i])
  let h = sha256(buf)
  for b in h: result.add b

proc checkDeliveryFirewall*(fwCfg: FirewallConfig, payload: openArray[byte]): bool =
  ## Check if an incoming data packet is allowed to be delivered to a local open port.
  if not fwCfg.enable or fwCfg.allowedOpenPorts.len == 0:
    return true
  let dPort = extractDestinationPort(payload)
  if int(dPort) notin fwCfg.allowedOpenPorts:
    stderr.writeLine "[firewall] incoming delivery dropped (port " & $dPort & " not in AllowedOpenPorts)"
    return false
  true

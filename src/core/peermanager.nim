## Peer discovery and self-healing state machine.
##
## This module deliberately separates peer *knowledge* from connection policy.
## Static peers are always eligible. Gossip/public/multicast peers are contact
## hints and may be dialed only if configuration allows it, preserving the
## Yggdrasil principle that nodes do not create arbitrary surprise peerings.

import std/[tables, options, times, strutils, sequtils, algorithm]
import ./types

type
  PeerSource* = enum psStatic, psMulticast, psPublicList, psGossip, psAdmin
  PeerConnectionState* = enum pcsDisconnected, pcsConnecting, pcsConnected, pcsSuspect, pcsDead

  PeerRecord* = object
    id*: Option[NodeId]
    uri*: PeerUri
    source*: PeerSource
    state*: PeerConnectionState
    lastSeen*: Time
    lastHeartbeat*: Time
    failures*: int
    allowAutoDial*: bool
    signature*: seq[byte]

  PeerManagerConfig* = object
    multicastEnabled*: bool
    peerExchangeEnabled*: bool
    heartbeatSeconds*: int
    suspectAfterSeconds*: int
    deadAfterSeconds*: int
    maxDialAttempts*: int

  PeerManager* = object
    peers*: Table[string, PeerRecord]
    cfg*: PeerManagerConfig

proc defaultPeerManagerConfig*(): PeerManagerConfig =
  PeerManagerConfig(multicastEnabled: true, peerExchangeEnabled: true,
                    heartbeatSeconds: 5, suspectAfterSeconds: 15,
                    deadAfterSeconds: 30, maxDialAttempts: 3)

proc initPeerManager*(cfg = defaultPeerManagerConfig()): PeerManager =
  PeerManager(peers: initTable[string, PeerRecord](), cfg: cfg)

proc parsePeerUri*(uri: string): PeerUri =
  let p = uri.find("://")
  if p <= 0: raise newException(ValueError, "peer URI must contain scheme://")
  result.scheme = uri[0 ..< p].toLowerAscii()
  result.kind = transportKind(result.scheme)
  let rest = uri[p + 3 .. ^1]
  if result.kind == tkUnix:
    result.path = rest
    result.host = ""
    result.port = 0
    return
  if rest.startsWith("["):
    let close = rest.find(']')
    if close < 0: raise newException(ValueError, "invalid bracketed IPv6 peer URI")
    result.host = rest[1 ..< close]
    if close + 1 < rest.len and rest[close + 1] == ':':
      result.port = parseInt(rest[close + 2 .. ^1])
    else:
      raise newException(ValueError, "peer URI missing port: " & uri)
  else:
    let colon = rest.rfind(':')
    if colon < 0: raise newException(ValueError, "peer URI missing port: " & uri)
    result.host = rest[0 ..< colon]
    result.port = parseInt(rest[colon + 1 .. ^1])
  if result.host.len == 0: raise newException(ValueError, "peer URI host is empty")
  if result.port <= 0 or result.port > 65535: raise newException(ValueError, "peer URI port out of range")

proc `$`*(u: PeerUri): string =
  if u.kind == tkUnix: u.scheme & "://" & u.path
  elif u.host.contains(':'): u.scheme & "://[" & u.host & "]:" & $u.port
  else: u.scheme & "://" & u.host & ":" & $u.port

proc addPeer*(pm: var PeerManager, uri: string, source: PeerSource = psAdmin,
              allowAutoDial = true, id = none(NodeId)): PeerRecord =
  let parsed = parsePeerUri(uri)
  let key = $parsed
  result = PeerRecord(id: id, uri: parsed, source: source, state: pcsDisconnected,
                      lastSeen: getTime(), lastHeartbeat: getTime(), failures: 0,
                      allowAutoDial: allowAutoDial)
  pm.peers[key] = result

proc removePeer*(pm: var PeerManager, uri: string): bool =
  let parsed = parsePeerUri(uri)
  let key = $parsed
  if pm.peers.hasKey(key):
    pm.peers.del(key)
    true
  else: false

proc markConnected*(pm: var PeerManager, uri: string, id: NodeId) =
  let key = $parsePeerUri(uri)
  if pm.peers.hasKey(key):
    pm.peers[key].state = pcsConnected
    pm.peers[key].id = some(id)
    pm.peers[key].lastSeen = getTime()
    pm.peers[key].lastHeartbeat = getTime()
    pm.peers[key].failures = 0

proc heartbeat*(pm: var PeerManager, uri: string) =
  let key = $parsePeerUri(uri)
  if pm.peers.hasKey(key):
    pm.peers[key].lastHeartbeat = getTime()
    pm.peers[key].lastSeen = getTime()
    if pm.peers[key].state in {pcsSuspect, pcsDead}: pm.peers[key].state = pcsConnected

proc markFailed*(pm: var PeerManager, uri: string) =
  let key = $parsePeerUri(uri)
  if pm.peers.hasKey(key):
    inc pm.peers[key].failures
    pm.peers[key].state = pcsDead
    pm.peers[key].lastSeen = getTime()

proc tick*(pm: var PeerManager, now = getTime()): seq[PeerRecord] =
  ## Update suspect/dead timers and return peers that should be dialed now.
  for k in pm.peers.keys.toSeq:
    var p = pm.peers[k]
    let silence = int((now - p.lastHeartbeat).inSeconds)
    if p.state == pcsConnected and silence >= pm.cfg.suspectAfterSeconds:
      p.state = pcsSuspect
    if p.state in {pcsConnected, pcsSuspect} and silence >= pm.cfg.deadAfterSeconds:
      p.state = pcsDead
      inc p.failures
    pm.peers[k] = p

  for p in pm.peers.values:
    if p.allowAutoDial and p.state in {pcsDisconnected, pcsDead} and p.failures < pm.cfg.maxDialAttempts:
      result.add p
  result.sort(proc(a, b: PeerRecord): int = cmp(a.failures, b.failures))

proc connectedPeers*(pm: PeerManager): seq[PeerRecord] =
  for p in pm.peers.values:
    if p.state == pcsConnected: result.add p

proc knownUris*(pm: PeerManager): seq[string] =
  for p in pm.peers.values: result.add $p.uri
  result.sort(system.cmp[string])

proc ingestPublicPeerList*(pm: var PeerManager, body: string) =
  for raw in body.splitLines():
    let line = raw.strip()
    if line.len == 0 or line.startsWith("#"): continue
    discard pm.addPeer(line, psPublicList, allowAutoDial = true)

proc ingestGossip*(pm: var PeerManager, uris: openArray[string], signed = false) =
  ## Signature verification is a production crypto-backend responsibility. The
  ## flag is retained so callers can fail closed before invoking this helper.
  if not pm.cfg.peerExchangeEnabled: return
  if not signed: return
  for uri in uris:
    if not pm.peers.hasKey($parsePeerUri(uri)):
      discard pm.addPeer(uri, psGossip, allowAutoDial = false)

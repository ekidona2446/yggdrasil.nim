## Kademlia-style DHT control plane.
##
## The DHT stores key -> tree coordinates and peer contact hints. It is never
## consulted by `tree.nextHop`; data-plane forwarding only sees coordinates.

import std/[tables, options, times, algorithm]
import ./types
import ../util/bytes

type
  DhtEntry* = object
    key*: NodeId
    coords*: Coordinates
    sequence*: uint64
    expiresAt*: Time
    signature*: seq[byte]
    publisher*: NodeId

  Contact* = object
    id*: NodeId
    coords*: Coordinates
    uri*: string
    lastSeen*: Time

  Dht* = object
    selfId*: NodeId
    entries*: Table[NodeId, DhtEntry]
    contacts*: Table[NodeId, Contact]
    k*: int
    entryTtlSeconds*: int

proc initDht*(selfId: NodeId, k = 20, entryTtlSeconds = 600): Dht =
  Dht(selfId: selfId, entries: initTable[NodeId, DhtEntry](),
      contacts: initTable[NodeId, Contact](), k: k, entryTtlSeconds: entryTtlSeconds)

proc putContact*(d: var Dht, c: Contact) = d.contacts[c.id] = c

proc put*(d: var Dht, key: NodeId, coords: Coordinates, publisher: NodeId,
          sequence: uint64, signature: openArray[byte] = []) =
  let expires = getTime() + initDuration(seconds = d.entryTtlSeconds)
  if d.entries.hasKey(key):
    let old = d.entries[key]
    if sequence < old.sequence: return
  var sig = newSeq[byte](signature.len)
  for i in 0 ..< signature.len: sig[i] = signature[i]
  d.entries[key] = DhtEntry(key: key, coords: coords, sequence: sequence,
                            expiresAt: expires, signature: sig,
                            publisher: publisher)

proc get*(d: Dht, key: NodeId): Option[DhtEntry] =
  if not d.entries.hasKey(key): return none(DhtEntry)
  let e = d.entries[key]
  if e.expiresAt < getTime(): return none(DhtEntry)
  some(e)

proc expire*(d: var Dht) =
  let now = getTime()
  var dead: seq[NodeId]
  for k, e in d.entries:
    if e.expiresAt < now: dead.add k
  for k in dead: d.entries.del k

proc distanceTo*(target, id: NodeId): Bytes32 = xorDistance(target, id)

proc closestContacts*(d: Dht, target: NodeId, limit = -1): seq[Contact] =
  for c in d.contacts.values: result.add c
  result.sort(proc(a, b: Contact): int = cmpDistance(distanceTo(target, a.id), distanceTo(target, b.id)))
  let n = if limit < 0: d.k else: min(limit, d.k)
  if result.len > n: result.setLen(n)

proc closestEntries*(d: Dht, target: NodeId, limit = -1): seq[DhtEntry] =
  for e in d.entries.values:
    if e.expiresAt >= getTime(): result.add e
  result.sort(proc(a, b: DhtEntry): int = cmpDistance(distanceTo(target, a.key), distanceTo(target, b.key)))
  let n = if limit < 0: d.k else: min(limit, d.k)
  if result.len > n: result.setLen(n)

proc refreshSelf*(d: var Dht, selfCoords: Coordinates, sequence: uint64) =
  ## Publish own current coordinate mapping.
  let seqBytes = u64le(sequence)
  let sig = hash256(concatBytes(d.selfId.bytes, seqBytes), "yggdrasil-dht-dev-sig")
  d.put(d.selfId, selfCoords, d.selfId, sequence, sig)

proc toJsonable*(e: DhtEntry): tuple[key: string, coords: string, sequence: uint64, publisher: string] =
  (toHex(e.key), coordToString(e.coords), e.sequence, toHex(e.publisher))

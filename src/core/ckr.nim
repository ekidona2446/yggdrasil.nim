## Crypto-Key Routing (CKR).
##
## CKR maps arbitrary IPv4/IPv6 subnets to destination node public keys. It is
## a VPN routing table above the Yggdrasil address plane. Ingress validation is
## mandatory: a remote node may only inject packets whose source address is
## covered by the route's allowed source subnets.

import std/[options, sequtils, strutils]
import ./types
import ../util/ipnet

type
  CkrMode* = enum ckrStatic, ckrDynamic

  CkrRoute* = object
    id*: string
    remoteKey*: NodeId
    destinationSubnets*: seq[IpNet]
    allowedSourceSubnets*: seq[IpNet]
    mode*: CkrMode
    enabled*: bool
    metric*: uint32

  CkrTable* = object
    routes*: seq[CkrRoute]

proc initCkrTable*(): CkrTable = CkrTable(routes: @[])

proc parseCkrRoute*(id: string, remoteKey: NodeId,
                    destinations, allowedSources: openArray[string],
                    dynamic = false, metric: uint32 = 100): CkrRoute =
  if id.strip().len == 0: raise newException(ValueError, "CKR route id is empty")
  result.id = id
  result.remoteKey = remoteKey
  for d in destinations: result.destinationSubnets.add parseIpNet(d)
  for s in allowedSources: result.allowedSourceSubnets.add parseIpNet(s)
  result.mode = if dynamic: ckrDynamic else: ckrStatic
  result.enabled = true
  result.metric = metric
  if result.destinationSubnets.len == 0:
    raise newException(ValueError, "CKR route must have at least one destination subnet")

proc addRoute*(t: var CkrTable, route: CkrRoute) =
  for i, r in t.routes:
    if r.id == route.id:
      t.routes[i] = route
      return
  t.routes.add route

proc removeRoute*(t: var CkrTable, id: string): bool =
  for i, r in t.routes:
    if r.id == id:
      t.routes.delete(i)
      return true
  false

proc listRoutes*(t: CkrTable): seq[CkrRoute] = t.routes

proc setEnabled*(t: var CkrTable, id: string, enabled: bool): bool =
  for i in 0 ..< t.routes.len:
    if t.routes[i].id == id:
      t.routes[i].enabled = enabled
      return true
  false

proc lookupRoute*(t: CkrTable, destination: IpAddress): Option[CkrRoute] =
  var best: Option[CkrRoute] = none(CkrRoute)
  var bestPrefix = -1
  var bestMetric = high(uint32)
  for r in t.routes:
    if not r.enabled: continue
    for n in r.destinationSubnets:
      if n.contains(destination):
        if n.prefixLen > bestPrefix or (n.prefixLen == bestPrefix and r.metric < bestMetric):
          best = some(r)
          bestPrefix = n.prefixLen
          bestMetric = r.metric
  best

proc lookupRoute*(t: CkrTable, destination: string): Option[CkrRoute] =
  t.lookupRoute(parseIpAddress(destination))

proc validateIngress*(route: CkrRoute, source: IpAddress): bool =
  ## Source-spoof prevention for packets entering from `route.remoteKey`.
  ## If no allowed sources are configured, fail closed.
  if not route.enabled: return false
  if route.allowedSourceSubnets.len == 0: return false
  for n in route.allowedSourceSubnets:
    if n.contains(source): return true
  false

proc validateIngress*(route: CkrRoute, source: string): bool = route.validateIngress(parseIpAddress(source))

proc validateIngress*(t: CkrTable, remoteKey: NodeId, source: IpAddress): bool =
  for r in t.routes:
    if r.remoteKey == remoteKey and r.validateIngress(source): return true
  false

proc routeSummary*(r: CkrRoute): string =
  let dst = r.destinationSubnets.mapIt($it).join(",")
  let src = r.allowedSourceSubnets.mapIt($it).join(",")
  r.id & " -> " & short(r.remoteKey) & " dst=[" & dst & "] src=[" & src & "] " & $r.mode

## Crypto-Key Routing (CKR) VPN engine.
##
## CKR maps arbitrary IPv4/IPv6 CIDR subnets to destination node public keys.
## Fully implements special syntax rules (inetv4, inetv6, ~, !) and robust
## source-spoof ingress validation exactly matching Rust's Yggdrasil-ng.

import std/[options, sequtils, strutils, tables]
import ./types
import ../util/ipnet
import ../config/configuration

type
  CkrMode* = enum ckrStatic, ckrDynamic

  CkrRoute* = object
    id*: string
    remoteKey*: NodeId
    destinationSubnets*: seq[IpNet]
    excludedSubnets*: seq[IpNet]
    allowedSourceSubnets*: seq[IpNet]
    mode*: CkrMode
    enabled*: bool
    noSystemRoute*: bool
    metric*: uint32

  CkrTable* = object
    routes*: seq[CkrRoute]

proc initCkrTable*(): CkrTable = CkrTable(routes: @[])

proc expandSpecialCidr*(spec: string): tuple[includes: seq[string], noSysRoute: bool, isExcl: bool] =
  var s = spec.strip()
  if s.len == 0: return
  
  result.isExcl = s.startsWith("!")
  if result.isExcl: s = s[1 .. ^1].strip()
  
  result.noSysRoute = s.startsWith("~")
  if result.noSysRoute: s = s[1 .. ^1].strip()

  case s.toLowerAscii()
  of "inetv4":
    # 0.0.0.0/1 and 128.0.0.0/1 cover all IPv4 cleanly without overriding default route
    result.includes = @["0.0.0.0/1", "128.0.0.0/1"]
  of "inetv6":
    # 2000::/3 covers all global unicast IPv6
    result.includes = @["2000::/3"]
  else:
    # Bare IP without prefix length is /32 or /128
    if not s.contains("/"):
      if s.contains(":"): result.includes = @[s & "/128"]
      else: result.includes = @[s & "/32"]
    else:
      result.includes = @[s]

proc parseCkrRoute*(id: string, remoteKey: NodeId,
                    destinations, allowedSources: openArray[string],
                    dynamic = false, metric: uint32 = 100): CkrRoute =
  if id.strip().len == 0: raise newException(ValueError, "CKR route id is empty")
  result.id = id
  result.remoteKey = remoteKey
  
  for d in destinations:
    let exp = expandSpecialCidr(d)
    if exp.isExcl:
      for sub in exp.includes: result.excludedSubnets.add parseIpNet(sub)
    else:
      if exp.noSysRoute: result.noSystemRoute = true
      for sub in exp.includes: result.destinationSubnets.add parseIpNet(sub)

  for s in allowedSources:
    let exp = expandSpecialCidr(s)
    if exp.isExcl:
      for sub in exp.includes: result.excludedSubnets.add parseIpNet(sub)
    else:
      for sub in exp.includes: result.allowedSourceSubnets.add parseIpNet(sub)

  result.mode = if dynamic: ckrDynamic else: ckrStatic
  result.enabled = true
  result.metric = metric
  if result.destinationSubnets.len == 0 and result.allowedSourceSubnets.len == 0:
    raise newException(ValueError, "CKR route must have at least one destination or source subnet")

proc addRoute*(t: var CkrTable, route: CkrRoute) =
  for i, r in t.routes:
    if r.id == route.id:
      t.routes[i] = route
      return
  t.routes.add route

proc populateFromTunnelConfig*(t: var CkrTable, cfg: TunnelRoutingConfig) =
  if not cfg.enable: return
  for keyHex, cidrs in cfg.remoteSubnets:
    try:
      let key = nodeIdFromHex(keyHex.strip())
      let route = parseCkrRoute("tunnel:" & short(key), key, cidrs, cidrs)
      t.addRoute(route)
    except CatchableError as e:
      stderr.writeLine "[ckr] invalid tunnel_routing entry for key " & keyHex & ": " & e.msg

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
    
    var isExcluded = false
    for excl in r.excludedSubnets:
      if excl.contains(destination): isExcluded = true; break
    if isExcluded: continue

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
  ## Source validation with exclusions.
  if not route.enabled: return false
  for excl in route.excludedSubnets:
    if excl.contains(source): return false
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
  let excl = r.excludedSubnets.mapIt($it).join(",")
  let src = r.allowedSourceSubnets.mapIt($it).join(",")
  r.id & " -> " & short(r.remoteKey) & " dst=[" & dst & "] excl=[" & excl & "] src=[" & src & "] " & $r.mode

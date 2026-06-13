## JSON-RPC 2.0 admin dispatcher.
##
## This module is transport-agnostic: Unix-domain/TCP listeners feed complete
## JSON documents into `dispatchRpc`. Persistent keepalive connections are just a
## stream of newline-delimited JSON-RPC requests using the same dispatcher.

import std/[json, options, tables]
import ../core/[identity, tree, dht, ckr, peermanager, types]

type
  AdminContext* = object
    identity*: NodeIdentity
    tree*: TreeState
    dht*: Dht
    ckr*: CkrTable
    peers*: PeerManager
    keepalive*: bool

proc initAdminContext*(identity: NodeIdentity, tree: TreeState, dht: Dht,
                       ckr: CkrTable, peers: PeerManager,
                       keepalive = true): AdminContext =
  AdminContext(identity: identity, tree: tree, dht: dht, ckr: ckr,
               peers: peers, keepalive: keepalive)

proc rpcSuccess(id: JsonNode, value: JsonNode): string =
  var resp = newJObject()
  resp["jsonrpc"] = %"2.0"
  resp["id"] = id
  resp["result"] = value
  $resp

proc rpcError(id: JsonNode, code: int, message: string): string =
  var err = newJObject()
  err["code"] = %code
  err["message"] = %message
  var resp = newJObject()
  resp["jsonrpc"] = %"2.0"
  resp["id"] = id
  resp["error"] = err
  $resp

proc arrayStrings(n: JsonNode, key: string): seq[string] =
  if n.kind != JObject or not n.hasKey(key): return @[]
  for x in n[key].items: result.add x.getStr()

proc paramStr(n: JsonNode, key: string, default = ""): string =
  if n.kind == JObject and n.hasKey(key): n[key].getStr() else: default

proc paramBool(n: JsonNode, key: string, default = false): bool =
  if n.kind == JObject and n.hasKey(key): n[key].getBool() else: default

proc paramInt(n: JsonNode, key: string, default = 0): int =
  if n.kind == JObject and n.hasKey(key): n[key].getInt() else: default

proc selfJson(ctx: AdminContext): JsonNode =
  result = newJObject()
  result["publicKey"] = %toHex(ctx.identity.publicKey)
  result["ipv6"] = %ctx.identity.addressString()
  result["treeRoot"] = %toHex(ctx.tree.rootId)
  result["coordinates"] = %coordToString(ctx.tree.selfCoords)
  result["revision"] = %ctx.tree.revision
  result["cryptoBackend"] = %($ctx.identity.backend)

proc peersJson(ctx: AdminContext): JsonNode =
  result = newJArray()
  for p in ctx.peers.peers.values:
    var item = newJObject()
    item["uri"] = %($p.uri)
    item["source"] = %($p.source)
    item["state"] = %($p.state)
    item["failures"] = %p.failures
    item["node"] = %(if p.id.isSome: toHex(p.id.get()) else: "")
    result.add item

proc dhtJson(ctx: AdminContext): JsonNode =
  result = newJArray()
  for e in ctx.dht.entries.values:
    var item = newJObject()
    item["key"] = %toHex(e.key)
    item["coordinates"] = %coordToString(e.coords)
    item["sequence"] = %e.sequence
    item["publisher"] = %toHex(e.publisher)
    result.add item

proc routesJson(ctx: AdminContext): JsonNode =
  result = newJArray()
  for r in ctx.ckr.routes:
    var dst = newJArray()
    for n in r.destinationSubnets: dst.add %($n)
    var src = newJArray()
    for n in r.allowedSourceSubnets: src.add %($n)
    var item = newJObject()
    item["id"] = %r.id
    item["remoteKey"] = %toHex(r.remoteKey)
    item["destinationSubnets"] = dst
    item["allowedSourceSubnets"] = src
    item["mode"] = %($r.mode)
    item["enabled"] = %r.enabled
    item["metric"] = %r.metric
    result.add item

proc obj1(key: string, value: JsonNode): JsonNode =
  result = newJObject()
  result[key] = value

proc dispatchMethod(ctx: var AdminContext, rpcMethod: string, params: JsonNode): JsonNode =
  case rpcMethod
  of "getSelf": result = selfJson(ctx)
  of "getPeers": result = peersJson(ctx)
  of "getDHT": result = dhtJson(ctx)
  of "getRoutes", "listCKRRoutes": result = routesJson(ctx)
  of "addPeer":
    let uri = paramStr(params, "uri")
    if uri.len == 0: raise newException(ValueError, "missing params.uri")
    let p = ctx.peers.addPeer(uri, psAdmin, allowAutoDial = true)
    result = newJObject()
    result["added"] = %true
    result["uri"] = %($p.uri)
  of "removePeer":
    let uri = paramStr(params, "uri")
    if uri.len == 0: raise newException(ValueError, "missing params.uri")
    result = obj1("removed", %ctx.peers.removePeer(uri))
  of "addCKRRoute":
    let rid = paramStr(params, "id")
    let remoteKey = nodeIdFromHex(paramStr(params, "remoteKey"))
    let destinations = arrayStrings(params, "destinationSubnets")
    let sources = arrayStrings(params, "allowedSourceSubnets")
    let dynamic = paramBool(params, "dynamic", false)
    let metric = uint32(paramInt(params, "metric", 100))
    let route = parseCkrRoute(rid, remoteKey, destinations, sources, dynamic, metric)
    ctx.ckr.addRoute(route)
    result = newJObject()
    result["added"] = %true
    result["id"] = %rid
  of "removeCKRRoute":
    let rid = paramStr(params, "id")
    result = obj1("removed", %ctx.ckr.removeRoute(rid))
  of "keepalive":
    ctx.keepalive = true
    result = obj1("keepalive", %true)
  else:
    raise newException(KeyError, "unknown admin method: " & rpcMethod)

proc dispatchRpc*(ctx: var AdminContext, request: string): string =
  var id = newJNull()
  try:
    let req = parseJson(request)
    if req.kind != JObject: return rpcError(id, -32600, "invalid request")
    if req.hasKey("id"): id = req["id"]
    if not req.hasKey("jsonrpc") or req["jsonrpc"].getStr() != "2.0":
      return rpcError(id, -32600, "invalid jsonrpc version")
    if not req.hasKey("method"):
      return rpcError(id, -32600, "missing method")
    let rpcMethodName = req["method"].getStr()
    let params = if req.hasKey("params"): req["params"] else: newJObject()
    result = rpcSuccess(id, dispatchMethod(ctx, rpcMethodName, params))
  except JsonParsingError as e:
    result = rpcError(id, -32700, e.msg)
  except KeyError as e:
    result = rpcError(id, -32601, e.msg)
  except CatchableError as e:
    result = rpcError(id, -32602, e.msg)

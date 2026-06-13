## Parser for the official Yggdrasil public peer JSON format.

import std/[json, tables, strutils, algorithm]
import ./types
import ./peermanager

type
  PublicPeer* = object
    region*: string
    uri*: string
    parsed*: PeerUri
    up*: bool
    key*: string
    responseMs*: int

  PublicPeerSummary* = object
    regions*: int
    total*: int
    up*: int
    usable*: int
    byScheme*: Table[string, int]

proc jsonBool(n: JsonNode, key: string, default = false): bool =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JBool: n[key].getBool() else: default

proc jsonInt(n: JsonNode, key: string, default = 0): int =
  if n.kind == JObject and n.hasKey(key) and n[key].kind in {JInt, JFloat}: n[key].getInt() else: default

proc jsonStr(n: JsonNode, key: string, default = ""): string =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JString: n[key].getStr() else: default

proc parsePublicPeersJson*(content: string; onlyUp = false): seq[PublicPeer] =
  let root = parseJson(content)
  if root.kind != JObject:
    raise newException(ValueError, "public peer list root must be a JSON object")
  for region, peersNode in root.pairs:
    if peersNode.kind != JObject: continue
    for uri, meta in peersNode.pairs:
      if meta.kind != JObject: continue
      let isUp = jsonBool(meta, "up", false)
      if onlyUp and not isUp: continue
      try:
        let parsed = parsePeerUri(uri)
        result.add PublicPeer(region: region, uri: uri, parsed: parsed, up: isUp,
                              key: jsonStr(meta, "key"),
                              responseMs: jsonInt(meta, "response_ms"))
      except CatchableError:
        ## Ignore entries with schemes or addresses this implementation does not
        ## understand, but keep summary.total independent in summarizePublicPeers.
        discard
  result.sort(proc(a, b: PublicPeer): int =
    if a.up != b.up: return cmp(ord(b.up), ord(a.up))
    if a.responseMs != b.responseMs: return cmp(a.responseMs, b.responseMs)
    cmp(a.uri, b.uri))

proc summarizePublicPeersJson*(content: string): PublicPeerSummary =
  let root = parseJson(content)
  if root.kind != JObject:
    raise newException(ValueError, "public peer list root must be a JSON object")
  result.byScheme = initTable[string, int]()
  result.regions = root.len
  for region, peersNode in root.pairs:
    discard region
    if peersNode.kind != JObject: continue
    for uri, meta in peersNode.pairs:
      inc result.total
      let scheme = uri.split("://", 1)[0].toLowerAscii()
      result.byScheme[scheme] = result.byScheme.getOrDefault(scheme) + 1
      if meta.kind == JObject and jsonBool(meta, "up", false): inc result.up
      try:
        discard parsePeerUri(uri)
        inc result.usable
      except CatchableError:
        discard

proc ingestPublicPeersJson*(pm: var PeerManager, content: string; onlyUp = true): int =
  for p in parsePublicPeersJson(content, onlyUp = onlyUp):
    if not pm.peers.hasKey($p.parsed):
      discard pm.addPeer(p.uri, psPublicList, allowAutoDial = true)
      inc result

proc `$`*(s: PublicPeerSummary): string =
  var parts: seq[string]
  for k, v in s.byScheme.pairs:
    parts.add k & "=" & $v
  parts.sort(system.cmp[string])
  "regions=" & $s.regions & " total=" & $s.total & " up=" & $s.up &
    " usable=" & $s.usable & " schemes=[" & parts.join(",") & "]"

## Public peer discovery and cache management.
##
## Supports two peer sources:
##   1. JSON API  – any URL that returns the publicnodes.json format
##      (publicpeers.neilalexander.dev or a self-hosted mirror).
##   2. GitHub Markdown repos – any "owner/repo" slug whose .md files contain
##      backtick-quoted peer URIs, exactly like yggdrasil-network/public-peers.
##      Uses the GitHub Trees API (single request, recursive=1) to list all .md
##      blobs, then fetches each raw file via raw.githubusercontent.com, so the
##      total API-counted calls is just 1 (the tree request). Respects the
##      X-RateLimit-* response headers and backs off when remaining ≤ 1.
##
## Both sources are deduplicated by URI before the caller sees them.
##
## Automatic refresh / health-check logic (driven by the daemon, not this module):
##   • peerCheckInterval  – "12h" | "1d" | "1w"  (parse → seconds)
##   • maxPingMs          – drop peers whose Ironwood handshake RTT exceeds this
##   • peerCacheFile      – persist the last good peer set as JSON

import std/[json, tables, strutils, sequtils, algorithm,
            httpclient, net, times, os]
import ./types
import ./peermanager

type
  PublicPeer* = object
    region*:     string   ## region slug from JSON key or dir/file path in repo
    uri*:        string   ## raw URI string
    parsed*:     PeerUri
    up*:         bool     ## JSON "up" field (absent when parsed from Markdown)
    key*:        string   ## optional pinned public key from JSON "key" field
    responseMs*: int      ## JSON "response_ms"; 0 when parsed from Markdown

  PublicPeerSummary* = object
    regions*:  int
    total*:    int
    up*:       int
    usable*:   int
    byScheme*: Table[string, int]

  ## Interval unit for peer refresh scheduling.
  PeerRefreshInterval* = object
    seconds*: int64   ## total seconds; 0 means "never"

  ## A cached peer entry written to / read from peerCacheFile.
  CachedPeer* = object
    uri*:        string
    region*:     string
    lastSeenMs*: int64   ## unix ms when last confirmed reachable
    pingMs*:     int     ## last measured Ironwood handshake RTT, –1 if unknown

proc parsePeerCheckInterval*(s: string): PeerRefreshInterval =
  ## Parse human-readable interval strings such as "30m", "12h", "1d", "1w".
  ## Returns seconds=0 on parse failure (meaning: never refresh).
  let t = s.strip().toLowerAscii()
  if t.len < 2: return PeerRefreshInterval(seconds: 0)
  try:
    let numPart = t[0 ..< t.len - 1]
    let unit    = t[^1]
    let n       = parseInt(numPart)
    let secs = case unit
      of 'm': int64(n) * 60
      of 'h': int64(n) * 3600
      of 'd': int64(n) * 86400
      of 'w': int64(n) * 604800
      else:   0'i64
    PeerRefreshInterval(seconds: secs)
  except ValueError:
    PeerRefreshInterval(seconds: 0)

proc jsonBool(n: JsonNode; key: string; default = false): bool =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JBool:
    n[key].getBool() else: default

proc jsonInt(n: JsonNode; key: string; default = 0): int =
  if n.kind == JObject and n.hasKey(key) and n[key].kind in {JInt, JFloat}:
    n[key].getInt() else: default

proc jsonStr(n: JsonNode; key: string; default = ""): string =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JString:
    n[key].getStr() else: default

proc parsePublicPeersJson*(content: string; onlyUp = false): seq[PublicPeer] =
  ## Parse the publicnodes.json format produced by publicpeers.neilalexander.dev.
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
        result.add PublicPeer(
          region:     region,
          uri:        uri,
          parsed:     parsed,
          up:         isUp,
          key:        jsonStr(meta, "key"),
          responseMs: jsonInt(meta, "response_ms"))
      except CatchableError:
        discard   # unknown scheme / malformed URI
  result.sort(proc(a, b: PublicPeer): int =
    if a.up != b.up: return cmp(ord(b.up), ord(a.up))
    if a.responseMs != b.responseMs: return cmp(a.responseMs, b.responseMs)
    cmp(a.uri, b.uri))

proc summarizePublicPeersJson*(content: string): PublicPeerSummary =
  let root = parseJson(content)
  if root.kind != JObject:
    raise newException(ValueError, "public peer list root must be a JSON object")
  result.byScheme = initTable[string, int]()
  result.regions  = root.len
  for _, peersNode in root.pairs:
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

## Allowed URI schemes extracted from Markdown peer lists.
const mdPeerSchemes = ["tcp://", "tls://", "quic://", "ws://", "wss://"]

proc extractUrisFromMarkdown*(content: string): seq[string] =
  var i = 0
  while i < content.len:
    # Find next backtick
    let bt = content.find('`', i)
    if bt < 0: break
    var schemeFound = false
    var scheme = ""
    for s in mdPeerSchemes:
      if content.len > bt + s.len and content[bt+1 ..< bt+1+s.len] == s:
        schemeFound = true
        scheme = s
        break
    if not schemeFound:
      i = bt + 1
      continue
    # Find closing backtick
    let closePos = content.find('`', bt + 1)
    if closePos < 0: break
    let uri = content[bt+1 ..< closePos]
    # Basic sanity: must contain "://" and end without whitespace
    if "://" in uri and uri.strip() == uri and uri.len > scheme.len:
      result.add uri
    i = closePos + 1

type
  GithubRateLimit* = object
    limit*:     int
    remaining*: int
    reset*:     int64   ## unix timestamp

proc headerOrDefault(headers: HttpHeaders; key: string; default: string): string =
  ## HttpHeaders doesn't expose getOrDefault with a fallback, so we access .table.
  let k = key.toLowerAscii()
  if headers.table.hasKey(k) and headers.table[k].len > 0:
    headers.table[k][0]
  else:
    default

proc parseRateLimit*(headers: HttpHeaders): GithubRateLimit =
  try: result.limit     = parseInt(headerOrDefault(headers, "x-ratelimit-limit",     "60"))  except: result.limit     = 60
  try: result.remaining = parseInt(headerOrDefault(headers, "x-ratelimit-remaining", "60"))  except: result.remaining = 60
  try: result.reset     = parseInt(headerOrDefault(headers, "x-ratelimit-reset",     "0"))   except: result.reset     = 0

proc slugToRegion*(path: string): string =
  ## Convert a repo-relative path like "europe/russia.md" → "europe/russia".
  result = path
  if result.endsWith(".md"): result = result[0 ..< result.len - 3]

proc fetchGithubMarkdownPeers*(
    repoSlug: string;
    token:    string = "";
    onlyUp:   bool   = false): seq[PublicPeer] =
  let parts = repoSlug.split('/', 1)
  if parts.len != 2:
    raise newException(ValueError, "githubPeerRepo must be 'owner/repo', got: " & repoSlug)
  let (owner, repo) = (parts[0], parts[1])

  var client = newHttpClient(timeout = 15_000)
  client.headers = newHttpHeaders({
    "User-Agent": "yggdrasil.nim/0.0.1",
    "Accept":     "application/vnd.github+json"
  })
  if token.len > 0:
    client.headers["Authorization"] = "Bearer " & token

  let treeUrl = "https://api.github.com/repos/" & owner & "/" & repo &
                "/git/trees/master?recursive=1"
  let treeResp = client.get(treeUrl)
  var rl = parseRateLimit(treeResp.headers)

  if treeResp.status[0] != '2':
    raise newException(IOError,
      "GitHub Trees API returned " & treeResp.status & " for " & treeUrl)

  let treeRoot = parseJson(treeResp.body)
  if treeRoot.kind != JObject:
    raise newException(ValueError, "unexpected GitHub tree response shape")

  # Collect blob paths for .md files (skip README at repo root)
  var mdPaths: seq[string]
  for item in treeRoot["tree"].items:
    if item.kind != JObject: continue
    let path = item["path"].getStr()
    let kind = item["type"].getStr()
    if kind == "blob" and path.endsWith(".md") and path != "README.md":
      mdPaths.add path

  var seen = initTable[string, bool]()
  for path in mdPaths:
    # Guard remaining quota (leave 1 spare for the caller)
    if rl.remaining <= 1:
      stderr.writeLine "[publicpeers] GitHub rate-limit nearly exhausted (" &
                       $rl.remaining & " remaining, resets at " & $rl.reset &
                       "), stopping early"
      break

    let rawUrl = "https://raw.githubusercontent.com/" &
                 owner & "/" & repo & "/master/" & path
    # raw.githubusercontent.com does NOT count against the core API quota,
    # so we only need to guard the tree + content API calls.
    let mdResp  = client.get(rawUrl)
    # raw host doesn't send X-RateLimit-*, no update needed here.

    if mdResp.status[0] != '2': continue

    let region = slugToRegion(path)
    for uri in extractUrisFromMarkdown(mdResp.body):
      if seen.hasKey(uri): continue
      seen[uri] = true
      try:
        let parsed = parsePeerUri(uri)
        result.add PublicPeer(
          region:     region,
          uri:        uri,
          parsed:     parsed,
          up:         false,
          key:        "",
          responseMs: 0)
      except CatchableError:
        discard

proc fetchText*(source: string): string =
  ## Fetch a URL or read a local file.  Raises IOError on failure.
  if source.startsWith("http://") or source.startsWith("https://"):
    var client = newHttpClient(
      timeout = 15_000,
      headers = newHttpHeaders({"User-Agent": "yggdrasil.nim/0.0.1"}))
    result = client.getContent(source)
  else:
    result = readFile(source)

proc fetchAllPeers*(
    jsonUrls:   seq[string];
    githubRepos: seq[string];
    onlyUp:     bool   = false;
    token:      string = ""): seq[PublicPeer] =
  ## Fetch from all configured sources (JSON URLs and/or GitHub repos),
  ## deduplicate by URI, and return the combined list.
  ##
  ## Sources are tried in order; errors are logged to stderr but do not abort
  ## the whole fetch — whatever succeeds is returned.
  var seen = initTable[string, bool]()
  var collected: seq[PublicPeer]

  template addIfNew(p: PublicPeer) =
    if not seen.hasKey(p.uri):
      seen[p.uri] = true
      collected.add p

  for url in jsonUrls:
    try:
      let content = fetchText(url)
      for p in parsePublicPeersJson(content, onlyUp = onlyUp):
        addIfNew(p)
    except CatchableError as e:
      stderr.writeLine "[publicpeers] JSON source " & url & " failed: " & e.msg

  for slug in githubRepos:
    try:
      for p in fetchGithubMarkdownPeers(slug, token = token, onlyUp = onlyUp):
        addIfNew(p)
    except CatchableError as e:
      stderr.writeLine "[publicpeers] GitHub repo " & slug & " failed: " & e.msg

  collected.sort(proc(a, b: PublicPeer): int =
    if a.up != b.up: return cmp(ord(b.up), ord(a.up))
    if a.responseMs != b.responseMs: return cmp(a.responseMs, b.responseMs)
    cmp(a.uri, b.uri))
  result = collected

proc savePeerCache*(path: string; peers: seq[PublicPeer]; pingTable: Table[string, int]) =
  ## Write the current peer set to a JSON cache file.
  ## pingTable maps URI → measured Ironwood handshake RTT in ms (–1 if unknown).
  var arr = newJArray()
  let nowMs = int64(getTime().toUnixFloat() * 1000)
  for p in peers:
    var obj = newJObject()
    obj["uri"]        = %p.uri
    obj["region"]     = %p.region
    obj["lastSeenMs"] = %nowMs
    obj["pingMs"]     = %(pingTable.getOrDefault(p.uri, -1))
    arr.add obj
  writeFile(path, $(%*{"version": 1, "peers": arr}))

proc loadPeerCache*(path: string): seq[CachedPeer] =
  ## Load the peer cache; returns empty on any error.
  if not fileExists(path): return @[]
  try:
    let root = parseJson(readFile(path))
    if root.kind != JObject: return @[]
    for item in root["peers"].items:
      if item.kind != JObject: continue
      result.add CachedPeer(
        uri:        item["uri"].getStr(),
        region:     item["region"].getStr(""),
        lastSeenMs: item["lastSeenMs"].getBiggestInt(0),
        pingMs:     item["pingMs"].getInt(-1))
  except CatchableError as e:
    stderr.writeLine "[publicpeers] cache load failed: " & e.msg

proc peerCacheAge*(path: string): int64 =
  ## Return the age in seconds of the cache file, or int64.high if not present.
  if not fileExists(path): return high(int64)
  try:
    let root = parseJson(readFile(path))
    if root.kind != JObject: return high(int64)
    var maxMs: int64 = 0
    for item in root["peers"].items:
      if item.kind != JObject: continue
      let ms = item["lastSeenMs"].getBiggestInt(0)
      if ms > maxMs: maxMs = ms
    if maxMs == 0: return high(int64)
    let nowMs = int64(getTime().toUnixFloat() * 1000)
    return (nowMs - maxMs) div 1000
  except CatchableError:
    return high(int64)

proc shouldRefreshCache*(path: string; interval: PeerRefreshInterval): bool =
  ## True when the cache is absent or older than the configured interval.
  if interval.seconds <= 0: return false   # "never" refresh
  peerCacheAge(path) >= interval.seconds

proc filterByPing*(peers: seq[PublicPeer]; pingTable: Table[string, int];
                   maxPingMs: int): seq[PublicPeer] =
  ## Keep peers whose measured ping is within maxPingMs.
  ## Peers with no measurement (pingMs = –1) are always kept.
  if maxPingMs <= 0: return peers
  for p in peers:
    let ms = pingTable.getOrDefault(p.uri, -1)
    if ms < 0 or ms <= maxPingMs:
      result.add p

proc ingestPublicPeers*(pm: var PeerManager; peers: seq[PublicPeer]): int =
  for p in peers:
    let key = p.uri
    if not pm.peers.hasKey(key):
      discard pm.addPeer(p.uri, psPublicList, allowAutoDial = true)
      inc result

proc ingestPublicPeersJson*(pm: var PeerManager; content: string;
                             onlyUp = true): int =
  ## Convenience wrapper used by the CLI --check-public-peers path.
  ingestPublicPeers(pm, parsePublicPeersJson(content, onlyUp = onlyUp))

proc `$`*(s: PublicPeerSummary): string =
  var parts: seq[string]
  for k, v in s.byScheme.pairs: parts.add k & "=" & $v
  parts.sort(system.cmp[string])
  "regions=" & $s.regions & " total=" & $s.total & " up=" & $s.up &
    " usable=" & $s.usable & " schemes=[" & parts.join(",") & "]"

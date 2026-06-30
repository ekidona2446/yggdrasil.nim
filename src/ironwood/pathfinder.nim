## Ironwood pathfinder state.
##
## Tracks pending lookup rumors and verified PathNotify results. Rumors are
## indexed by the bloom-transformed key (matching Go ironwood's behavior), so a
## PathLookup for a partial/transformed key can be matched against a PathNotify
## whose source is the responder's full public key.

import std/[tables, options, monotimes]
import ../core/types
import ./wire
import ./router

type
  PathInfo* = object
    seq*: uint64
    path*: Path
    broken*: bool
    lastRefresh*: MonoTime

  PathRumor* = object
    sendTime*: Option[MonoTime]
    created*: MonoTime

  Pathfinder* = object
    paths*: Table[NodeId, PathInfo]
    rumors*: Table[NodeId, PathRumor]

proc initPathfinder*(): Pathfinder =
  Pathfinder(paths: initTable[NodeId, PathInfo](), rumors: initTable[NodeId, PathRumor]())

proc ensureRumor*(pf: var Pathfinder, dest: NodeId): bool =
  ## Go ironwood stores path rumors under bloomTransform(dest), not necessarily
  ## under the exact destination key. This lets a lookup sent for an address or
  ## subnet partial key match a PathNotify whose source is the full Ed25519 key.
  let xform = bloomTransform(dest)
  if pf.rumors.hasKey(xform): return false
  pf.rumors[xform] = PathRumor(sendTime: none(MonoTime), created: getMonoTime())
  true

proc markLookupSent*(pf: var Pathfinder, dest: NodeId, now = getMonoTime()) =
  let xform = bloomTransform(dest)
  if not pf.rumors.hasKey(xform): discard pf.ensureRumor(dest)
  pf.rumors[xform].sendTime = some(now)

proc hasPath*(pf: Pathfinder, dest: NodeId): bool = pf.paths.hasKey(dest) and not pf.paths[dest].broken

proc getPath*(pf: Pathfinder, dest: NodeId): Option[Path] =
  if pf.hasPath(dest): some(pf.paths[dest].path) else: none(Path)

proc acceptNotify*(pf: var Pathfinder, notify: PathNotify): bool =
  ## Accept a notify if it is signed by the advertised source and either updates
  ## a known path with a higher sequence or satisfies a pending rumor.
  let sig = notify.info.signature.toSig64()
  let sigOk = verifyPathInfo(notify.source, notify.info.seq, notify.info.path, sig)
  if not sigOk:
    when defined(yggdebug): stderr.writeLine "[pathfinder] acceptNotify SIG-FAIL source=" & toHex(notify.source)
    return false
  if pf.paths.hasKey(notify.source):
    var old = pf.paths[notify.source]
    if notify.info.seq <= old.seq:
      when defined(yggdebug): stderr.writeLine "[pathfinder] acceptNotify OLD-SEQ source=" & toHex(notify.source)
      return false
    if not old.broken and old.path == notify.info.path:
      when defined(yggdebug): stderr.writeLine "[pathfinder] acceptNotify SAME-PATH source=" & toHex(notify.source)
      return false
  else:
    ## Check if the bloom-transformed source key matches a pending rumor. This
    ## mirrors Go's pathfinder: rumors are indexed by bloomTransform(lookup.dest)
    ## and not by the exact address/subnet partial key.
    let xform = bloomTransform(notify.source)
    var matched = pf.rumors.hasKey(xform)
    var firstRumor = ""
    if not matched:
      # Be tolerant while older code/long-running tests may still have exact
      # partial rumors around.
      let responderAddr = deriveYggAddress(notify.source)
      let addressPartial = keyPrefixForYggAddress(responderAddr)
      for rumorKey, _ in pf.rumors:
        if firstRumor.len == 0: firstRumor = toHex(rumorKey)
        if rumorKey == notify.source or rumorKey == addressPartial:
          matched = true
          break
    if not matched:
      when defined(yggdebug): stderr.writeLine "[pathfinder] acceptNotify NO-RUMOR source=" & toHex(notify.source) & " xform=" & toHex(xform) & " rumors=" & $pf.rumors.len & " firstRumor=" & firstRumor
      return false
  pf.paths[notify.source] = PathInfo(seq: notify.info.seq, path: notify.info.path,
                                     broken: false, lastRefresh: getMonoTime())
  let xformDone = bloomTransform(notify.source)
  if pf.rumors.hasKey(xformDone): pf.rumors.del(xformDone)
  if pf.rumors.hasKey(notify.source): pf.rumors.del(notify.source)
  let responderAddrDone = deriveYggAddress(notify.source)
  let addressPartialDone = keyPrefixForYggAddress(responderAddrDone)
  if pf.rumors.hasKey(addressPartialDone): pf.rumors.del(addressPartialDone)
  when defined(yggdebug): stderr.writeLine "[pathfinder] acceptNotify OK source=" & toHex(notify.source)
  true

proc markBroken*(pf: var Pathfinder, dest: NodeId) =
  if pf.paths.hasKey(dest): pf.paths[dest].broken = true

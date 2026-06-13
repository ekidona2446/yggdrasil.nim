## Minimal Ironwood pathfinder state.
##
## Tracks pending lookup rumors and verified PathNotify results. This is enough
## to begin wiring path discovery callbacks before the full bloom-target multicast
## implementation lands.

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
  if pf.rumors.hasKey(dest): return false
  pf.rumors[dest] = PathRumor(sendTime: none(MonoTime), created: getMonoTime())
  true

proc markLookupSent*(pf: var Pathfinder, dest: NodeId, now = getMonoTime()) =
  if not pf.rumors.hasKey(dest): discard pf.ensureRumor(dest)
  pf.rumors[dest].sendTime = some(now)

proc hasPath*(pf: Pathfinder, dest: NodeId): bool = pf.paths.hasKey(dest) and not pf.paths[dest].broken

proc getPath*(pf: Pathfinder, dest: NodeId): Option[Path] =
  if pf.hasPath(dest): some(pf.paths[dest].path) else: none(Path)

proc acceptNotify*(pf: var Pathfinder, notify: PathNotify): bool =
  ## Accept a notify if it is signed by the advertised source and either updates
  ## a known path with a higher sequence or satisfies a pending rumor.
  let sig = notify.info.signature.toSig64()
  if not verifyPathInfo(notify.source, notify.info.seq, notify.info.path, sig):
    return false
  if pf.paths.hasKey(notify.source):
    var old = pf.paths[notify.source]
    if notify.info.seq <= old.seq: return false
    if not old.broken and old.path == notify.info.path: return false
  elif not pf.rumors.hasKey(notify.source):
    ## Full Yggdrasil indexes rumors by transformed key. Until bloom transform is
    ## implemented, use source key as the minimal debug path.
    return false
  pf.paths[notify.source] = PathInfo(seq: notify.info.seq, path: notify.info.path,
                                     broken: false, lastRefresh: getMonoTime())
  if pf.rumors.hasKey(notify.source): pf.rumors.del(notify.source)
  true

proc markBroken*(pf: var Pathfinder, dest: NodeId) =
  if pf.paths.hasKey(dest): pf.paths[dest].broken = true

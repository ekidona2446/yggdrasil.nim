import std/[unittest, options]
import ../src/crypto/sodium
import ../src/ironwood/[pathfinder, router, wire]

suite "ironwood pathfinder":
  test "accepts signed path notify for pending rumor when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping pathfinder crypto assertions")
      check true
    else:
      let src = newRouterCrypto()
      var pf = initPathfinder()
      discard pf.ensureRumor(src.publicKey)
      let path = @[1'u64, 2, 3]
      let sig = src.signPathInfo(10, path).toArr64()
      let notify = PathNotify(source: src.publicKey, dest: src.publicKey, path: @[], watermark: high(uint64),
                              info: PathNotifyInfo(seq: 10, path: path, signature: sig))
      check pf.acceptNotify(notify)
      check pf.hasPath(src.publicKey)
      check pf.getPath(src.publicKey).get() == path

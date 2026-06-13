import std/[unittest, options]
import ../src/crypto/sodium
import ../src/ironwood/router
import ../src/ironwood/wire

suite "ironwood router signing":
  test "root announce signs and verifies when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping runtime router crypto assertions")
      check true
    else:
      let c = newRouterCrypto()
      let ann = makeRootAnnounce(c, 1, 2)
      check ann.check()
      let wire = ann.toWire().encodeAnnounce()
      let dec = decodeAnnounce(wire)
      check dec.isSome
      check fromWireAnnounce(dec.get()).check()

  test "path info signs and verifies when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping runtime router crypto assertions")
      check true
    else:
      let c = newRouterCrypto()
      let path = @[1'u64, 2, 300]
      let sig = c.signPathInfo(7, path)
      check verifyPathInfo(c.publicKey, 7, path, sig)
      check not verifyPathInfo(c.publicKey, 8, path, sig)

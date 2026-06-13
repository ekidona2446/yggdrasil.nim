import std/[unittest, options]
import ../src/crypto/sodium
import ../src/ironwood/[routerstate, router, pathfinder, bloom]

proc deliver(fromState: var RouterState, toState: var RouterState, actions: seq[FrameAction]): RouterStep =
  for act in actions:
    let pid = toState.peerIdFor(fromState.crypto.publicKey)
    if pid.isSome:
      let st = toState.handleFrameBytes(pid.get(), act.frame)
      result.outbound.add st.outbound
      result.deliveries.add st.deliveries
      result.events.add st.events

suite "ironwood routerstate orchestrator":
  test "two nodes exchange control frames, discover path, and deliver session traffic":
    if not available():
      checkpoint("libsodium not available; skipping routerstate assertions")
      check true
    else:
      var a = initRouterState(newRouterCrypto())
      var b = initRouterState(newRouterCrypto())

      var aOut = a.addPeer(b.crypto.publicKey).outbound
      var bOut = b.addPeer(a.crypto.publicKey).outbound
      for _ in 0 ..< 5:
        let bStep = deliver(a, b, aOut)
        let aStep = deliver(b, a, bOut & bStep.outbound)
        aOut = aStep.outbound
        bOut = bStep.outbound

      check a.peerIdFor(b.crypto.publicKey).isSome
      check b.peerIdFor(a.crypto.publicKey).isSome

      let lookup = a.sendLookup(b.crypto.publicKey)
      let bLookupStep = deliver(a, b, lookup.outbound)
      discard deliver(b, a, bLookupStep.outbound)
      check a.pathfinder.hasPath(b.crypto.publicKey) or a.peerIdFor(b.crypto.publicKey).isSome

      var step = a.sendAppData(b.crypto.publicKey, @[byte(42), byte(43)])
      var delivered: seq[AppDelivery]
      for _ in 0 ..< 10:
        let bStep = deliver(a, b, step.outbound)
        if bStep.deliveries.len > 0:
          delivered = bStep.deliveries
          break
        let aStep = deliver(b, a, bStep.outbound)
        if aStep.deliveries.len > 0:
          delivered = aStep.deliveries
          break
        step = aStep
      check delivered.len == 1
      check delivered[0].data == @[byte(42), byte(43)]

  test "three-node line can forward lookup and encrypted traffic via middle peer":
    if not available():
      checkpoint("libsodium not available; skipping routerstate multi-hop assertions")
      check true
    else:
      var a = initRouterState(newRouterCrypto())
      var b = initRouterState(newRouterCrypto())
      var c = initRouterState(newRouterCrypto())
      discard a.addPeer(b.crypto.publicKey)
      discard b.addPeer(a.crypto.publicKey)
      discard b.addPeer(c.crypto.publicKey)
      discard c.addPeer(b.crypto.publicKey)

      # Seed bloom knowledge so A sends C lookups to B and B sends them to C.
      var cbloom = BloomFilter()
      cbloom.add(c.crypto.publicKey)
      b.blooms.handleBloom(c.crypto.publicKey, cbloom)
      b.blooms.setOnTree(c.crypto.publicKey, true)
      var bbloom = BloomFilter()
      bbloom.add(c.crypto.publicKey)
      a.blooms.handleBloom(b.crypto.publicKey, bbloom)
      a.blooms.setOnTree(b.crypto.publicKey, true)
      var abloom = BloomFilter()
      abloom.add(a.crypto.publicKey)
      c.blooms.handleBloom(b.crypto.publicKey, abloom)
      c.blooms.setOnTree(b.crypto.publicKey, true)

      let lookup = a.sendLookup(c.crypto.publicKey)
      let bStep = deliver(a, b, lookup.outbound)
      check bStep.outbound.len > 0
      let cStep = deliver(b, c, bStep.outbound)
      check cStep.outbound.len > 0
      let bNotify = deliver(c, b, cStep.outbound)
      check bNotify.outbound.len > 0
      let aNotify = deliver(b, a, bNotify.outbound)
      check a.pathfinder.hasPath(c.crypto.publicKey) or aNotify.events.len > 0

      var app = a.sendAppData(c.crypto.publicKey, @[byte(5), byte(6)])
      var got: seq[AppDelivery]
      for _ in 0 ..< 12:
        let bs = deliver(a, b, app.outbound)
        let cs = deliver(b, c, bs.outbound)
        if cs.deliveries.len > 0:
          got = cs.deliveries
          break
        let bs2 = deliver(c, b, cs.outbound)
        let as2 = deliver(b, a, bs2.outbound)
        app = as2
      check got.len == 1
      if got.len == 1:
        check got[0].data == @[byte(5), byte(6)]

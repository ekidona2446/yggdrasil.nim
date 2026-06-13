import std/[unittest, options, tables]
import ../src/crypto/sodium
import ../src/ironwood/[peer, router]

suite "ironwood peer state machine":
  test "SigReq/SigRes/Announce exchange works and records RTT when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping peer crypto assertions")
      check true
    else:
      let ca = newRouterCrypto()
      let cb = newRouterCrypto()
      var a = initIronwoodPeer(1, cb.publicKey, ca, localPort = 7)
      var b = initIronwoodPeer(2, ca.publicKey, cb, localPort = 9)
      let reqFrame = a.makeSigReq(12345)
      let bStep = b.handleFrameBytes(reqFrame)
      check bStep.events.len >= 1
      check bStep.events[0].kind == peSigReqReceived
      check bStep.outbound.len == 1
      let aStep = a.handleFrameBytes(bStep.outbound[0])
      check aStep.events.len >= 1
      check aStep.events[0].kind == peSigResReceived
      check aStep.events[0].rttMs.isSome
      check aStep.outbound.len == 1
      let bAnnStep = b.handleFrameBytes(aStep.outbound[0])
      check bAnnStep.events.len >= 1
      check bAnnStep.events[0].kind == peAnnounceAccepted
      check b.announces.hasKey(ca.publicKey)

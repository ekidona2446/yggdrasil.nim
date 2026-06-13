import std/[unittest, options, monotimes, times, os]
import ../src/ironwood/router

suite "ironwood RTT tracking":
  test "RTT is measured from each SigReq send time, not peer connection start":
    var r = initRttTracker()
    let peer: PeerId = 42
    let connectionStart = getMonoTime()
    sleep(20)
    r.markSigReqSent(peer)
    sleep(15)
    let rtt = r.handleSigResReceived(peer)
    check rtt.isSome
    check rtt.get() >= 10
    check rtt.get() < 200
    # If measured from connectionStart it would include both sleeps.
    let wrong = (getMonoTime() - connectionStart).inMilliseconds
    check wrong > rtt.get()

  test "missing SigReq send timestamp returns none":
    var r = initRttTracker()
    check r.handleSigResReceived(99).isNone

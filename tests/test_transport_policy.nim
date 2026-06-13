import std/unittest
import ../src/core/types
import ../src/transport/[peertcp, peerquic]

suite "transport policy":
  test "no TCP-over-TCP":
    check not canCarryInner(tkTcp, ipTcp)
    check not canCarryInner(tkTls, ipTcp)
    check not canCarryInner(tkWebSocket, ipTcp)
    check canCarryInner(tkQuic, ipTcp)
    check canCarryInner(tkTcp, ipUdp)

  test "QUIC peer accepts inner TCP":
    let uri = PeerUri(scheme: "quic", host: "127.0.0.1", port: 12345, kind: tkQuic)
    let q = openQuicPeer(uri)
    check q.canCarryInner(ipTcp)

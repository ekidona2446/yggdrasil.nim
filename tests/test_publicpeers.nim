import std/unittest
import ../src/core/[publicpeers, peermanager]

const sample = """
{
  "armenia.md": {
    "quic://37.186.113.100:1515": {"up": true, "key": "abc", "response_ms": 123},
    "tcp://37.186.113.100:1514": {"up": true, "key": "abc", "response_ms": 122},
    "tls://37.186.113.100:1515": {"up": false}
  },
  "test.md": {
    "wss://example.com:443": {"up": true, "response_ms": 5}
  }
}
"""

suite "public peer parser":
  test "parses official JSON shape and ingests up peers":
    let summary = summarizePublicPeersJson(sample)
    check summary.regions == 2
    check summary.total == 4
    check summary.up == 3
    check summary.usable == 4
    let peers = parsePublicPeersJson(sample, onlyUp = true)
    check peers.len == 3
    check peers[0].uri == "wss://example.com:443"
    var pm = initPeerManager()
    check pm.ingestPublicPeersJson(sample, onlyUp = true) == 3
    check pm.knownUris().len == 3

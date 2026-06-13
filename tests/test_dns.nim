import std/[unittest, options]
import ../src/dns/localdns
import ../src/util/hostsfile
import ../src/core/[identity, dht, types]
import ../src/util/bytes

suite "local dns":
  test "localhost DNS listen expands to IPv4 and IPv6 loopbacks":
    let specs = parseListen("localhost:5053")
    check specs.len == 2

  test "hosts precedes dht and dht resolves internal hex names":
    var seed: Bytes32
    for i in 0 ..< 32: seed[i] = byte(i)
    let id = identityFromSeed(seed)
    var d = initDht(id.publicKey)
    d.put(id.publicKey, @[], id.publicKey, 1)
    var s = initLocalDnsServer(LocalDnsConfig(enable: true, listen: "127.0.0.1:5053",
                                             internalDomain: ".yg", hostsPath: "",
                                             upstream: @[]))
    s.hosts = parseHostsContent("10.0.0.1 override.yg\n")
    check s.resolveName(d, "override.yg").kind == dnsHosts
    let name = toHex(id.publicKey) & ".yg"
    let ans = s.resolveName(d, name)
    check ans.kind == dnsDht
    check ans.ipv6.isSome

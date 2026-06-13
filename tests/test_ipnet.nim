import std/unittest
import ../src/util/ipnet

suite "ipnet":
  test "IPv4 CIDR contains":
    let n = parseIpNet("10.42.0.0/16")
    check n.contains("10.42.1.2")
    check not n.contains("10.43.1.2")

  test "IPv6 CIDR contains with compression":
    let n = parseIpNet("fd00:abcd::/32")
    check n.contains("fd00:abcd::1")
    check n.contains("fd00:abcd:0:1::1234")
    check not n.contains("fd00:abce::1")

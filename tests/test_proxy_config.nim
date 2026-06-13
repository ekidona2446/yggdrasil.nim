import std/unittest
import ../src/transport/proxy

suite "proxy config":
  test "localhost listen expands to IPv4 and IPv6 loopbacks":
    let specs = parseListen("localhost:1080")
    check specs.len == 2

  test "bracketed IPv6 listen parses":
    let specs = parseListen("[::1]:1080")
    check specs.len == 1

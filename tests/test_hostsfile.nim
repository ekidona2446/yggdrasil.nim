import std/[unittest, options]
import ../src/util/hostsfile

suite "hostsfile":
  test "hosts precedence parser":
    let h = parseHostsContent("""
# comment
127.0.0.1 localhost loopback
fd00::1 node.yg node
""")
    check h.resolve("localhost").isSome
    check h.resolve("node.yg").isSome
    check h.resolve("missing").isNone

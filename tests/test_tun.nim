import std/[unittest, options]
import ../src/tun/tunadapter
import ../src/core/types

suite "tun utilities":
  test "IPv4-over-IPv6 encapsulation round-trip":
    var src, dst: IPv6Address
    src[0] = 0xfd'u8
    dst[0] = 0xfd'u8
    dst[15] = 1'u8
    let ipv4 = @[byte(0x45), byte(0), byte(0), byte(20), byte(0), byte(0), byte(0), byte(0),
                 byte(64), byte(6), byte(0), byte(0), byte(10), byte(0), byte(0), byte(1),
                 byte(10), byte(0), byte(0), byte(2)]
    let outer = encapsulate4in6(src, dst, ipv4)
    check outer[6] == 4'u8
    let inner = decapsulate4in6(outer)
    check inner.isSome
    check inner.get() == ipv4
    check detectInnerProtocol(ipv4) == ipTcp

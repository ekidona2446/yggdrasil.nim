import std/[unittest, options]
import ../src/ironwood/wire
import ../src/core/types

suite "ironwood wire":
  test "uvarint roundtrip":
    for v in [0'u64, 1, 127, 128, 255, 256, 16383, 16384, high(uint64) shr 1]:
      let enc = encodeUvarint(v)
      let dec = decodeUvarint(enc)
      check dec.isSome
      check dec.get().value == v
      check dec.get().consumed == enc.len
      check enc.len == uvarintSize(v)

  test "path roundtrip":
    let p = @[1'u64, 2, 300, 65535]
    let enc = encodePath(p)
    let dec = decodePath(enc)
    check dec.isSome
    check dec.get().path == p
    check dec.get().consumed == enc.len

  test "frame roundtrip":
    let frame = encodeFrame(iwTraffic, @[byte(1), byte(2), byte(3)])
    let dec = decodeFrame(frame)
    check dec.isSome
    check dec.get().packetType == iwTraffic
    check dec.get().payload == @[byte(1), byte(2), byte(3)]
    check dec.get().consumed == frame.len

  test "traffic roundtrip":
    var src, dst: NodeId
    for i in 0 ..< 32:
      src.bytes[i] = byte(i)
      dst.bytes[i] = byte(255 - i)
    let t = Traffic(path: @[1'u64, 2], fromPath: @[3'u64], source: src, dest: dst,
                    watermark: 42, payload: @[byte(9), byte(8)])
    let frame = encodeTrafficFrame(t)
    let decFrame = decodeFrame(frame)
    check decFrame.isSome
    let dec = decodeTraffic(decFrame.get().payload)
    check dec.isSome
    check dec.get().path == t.path
    check dec.get().fromPath == t.fromPath
    check dec.get().source == src
    check dec.get().dest == dst
    check dec.get().watermark == 42
    check dec.get().payload == t.payload

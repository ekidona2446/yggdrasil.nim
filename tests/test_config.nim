import std/[unittest, os]
import ../src/config/configuration

suite "configuration":
  test "multiline arrays tolerate IPv6 brackets inside quoted URIs":
    let path = getTempDir() / "ydrasil-config-test.toml"
    writeFile(path, """
[Peers]
static = [
  "quic://203.0.113.10:12345",
  "tcp+tls://[2001:db8::10]:12345",
]
[Admin]
listen = ["unix://ydrasil-admin.sock", "tcp://127.0.0.1:9001"]
""")
    let cfg = loadConfig(path)
    check cfg.peers.staticPeers.len == 2
    check cfg.peers.staticPeers[1] == "tcp+tls://[2001:db8::10]:12345"
    check cfg.admin.listen.len == 2
    removeFile(path)

  test "example config loads":
    let cfg = loadConfig("config.example.toml")
    check cfg.node.keyfile.len > 0
    check cfg.peers.staticPeers.len == 2
    check cfg.admin.listen.len >= 1

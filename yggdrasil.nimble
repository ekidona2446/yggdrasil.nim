# Package definition for yggdrasil-nim.

version       = "0.0.1"
author        = "nierneon"
description   = "A Nim reimplementation scaffold of the Yggdrasil mesh network architecture"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["yggdrasil"]

# Required for HTTPS public peer-list fetching through std/httpclient.
switch("define", "ssl")

requires "nim >= 1.6.14"

# Intended production dependencies. They are not imported by the default dev
# backend so the project remains buildable on systems without native drivers.
# requires "chronos >= 4.0.0"
# requires "nimcrypto >= 0.6.0"
# requires "json_rpc >= 0.3.0"

# Common tasks:
#   nimble test
#   nimble sim
#   nimble run -- --config=config.example.toml --proxy

task test, "Run unit tests":
  exec "nim c -r tests/test_identity.nim"
  exec "nim c -r tests/test_ipnet.nim"
  exec "nim c -r tests/test_tree.nim"
  exec "nim c -r tests/test_ckr.nim"
  exec "nim c -r tests/test_hostsfile.nim"
  exec "nim c -r tests/test_crypto.nim"
  exec "nim c -r tests/test_transport_policy.nim"
  exec "nim c -r tests/test_dns.nim"
  exec "nim c -r tests/test_tun.nim"
  exec "nim c -r tests/test_admin.nim"
  exec "nim c -r tests/test_config.nim"
  exec "nim c -r tests/test_publicpeers.nim"
  exec "nim c -r tests/test_proxy_config.nim"
  exec "nim c -r tests/test_ironwood_wire.nim"
  exec "nim c -r tests/test_ironwood_bloom.nim"
  exec "nim c -r tests/test_ironwood_session.nim"
  exec "nim c -r tests/test_ironwood_router.nim"
  exec "nim c -r tests/test_monocypher_backend.nim"
  exec "nim c -r tests/test_ironwood_rtt.nim"
  exec "nim c -r tests/test_ironwood_peer.nim"
  exec "nim c -r tests/test_ironwood_pathfinder.nim"
  exec "nim c -r tests/test_ironwood_routerstate.nim"

task sim, "Run self-healing/routing convergence simulation":
  exec "nim c -r simulation/self_healing_sim.nim"

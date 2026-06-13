import std/[unittest, json, strutils]
import ../src/core/[identity, tree, dht, ckr, peermanager, types]
import ../src/admin/api
import ../src/util/bytes

suite "admin api":
  test "getSelf and dynamic route verbs":
    var seed: Bytes32
    for i in 0 ..< 32: seed[i] = byte(i)
    let id = identityFromSeed(seed)
    var tr = initTree(id.publicKey)
    var dd = initDht(id.publicKey)
    dd.refreshSelf(tr.selfCoords, tr.revision)
    var ctx = initAdminContext(id, tr, dd, initCkrTable(), initPeerManager())

    let selfResp = parseJson(ctx.dispatchRpc("""{"jsonrpc":"2.0","id":1,"method":"getSelf"}"""))
    check selfResp["result"]["publicKey"].getStr() == toHex(id.publicKey)

    let addPeer = parseJson(ctx.dispatchRpc("""{"jsonrpc":"2.0","id":2,"method":"addPeer","params":{"uri":"quic://127.0.0.1:12345"}}"""))
    check addPeer["result"]["added"].getBool()

    let routeReq = """{"jsonrpc":"2.0","id":3,"method":"addCKRRoute","params":{"id":"r1","remoteKey":"REPLACEME","destinationSubnets":["10.1.0.0/16"],"allowedSourceSubnets":["10.2.0.0/16"],"dynamic":true}}""".replace("REPLACEME", toHex(id.publicKey))
    let routeResp = parseJson(ctx.dispatchRpc(routeReq))
    check routeResp["result"]["added"].getBool()
    let listResp = parseJson(ctx.dispatchRpc("""{"jsonrpc":"2.0","id":4,"method":"listCKRRoutes"}"""))
    check listResp["result"].len == 1

import std/[unittest, options]
import ../src/crypto/sodium
import ../src/ironwood/session

suite "ironwood session crypto":
  test "session init/ack encrypts, decrypts, and verifies signature when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping runtime crypto assertions")
      check true
    else:
      let a = newEdKeyPair()
      let b = newEdKeyPair()
      let aCur = newCurve25519Keypair()
      let aNext = newCurve25519Keypair()
      let init = SessionInit(current: aCur.pk, next: aNext.pk, keySeq: 0, seq: 123)
      let wire = init.encrypt(a, b.publicKey, SessionTypeInit)
      check wire.len == SessionInitSize
      let bCurveSk = edSecretToCurve25519(b.secretKey)
      let dec = decryptSessionInit(wire, bCurveSk, a.publicKey)
      check dec.isSome
      check dec.get().msgType == SessionTypeInit
      check dec.get().init.current == aCur.pk
      check dec.get().init.next == aNext.pk
      check dec.get().init.seq == 123

  test "traffic encrypts and decrypts when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping runtime crypto assertions")
      check true
    else:
      let remote = newCurve25519Keypair()
      let local = newCurve25519Keypair()
      let next = newCurve25519Keypair()
      let msg = @[byte(1), byte(2), byte(3)]
      let enc = encryptTraffic(0, 0, 1, next.pk, msg, remote.pk, local.sk)
      let dec = decryptTraffic(enc, local.pk, remote.sk)
      check dec.isSome
      check dec.get().header.nonce == 1
      check dec.get().nextPub == next.pk
      check dec.get().payload == msg

suite "ironwood session manager":
  test "two managers establish session and deliver one payload when libsodium is available":
    if not available():
      checkpoint("libsodium not available; skipping session manager assertions")
      check true
    else:
      let aKey = newEdKeyPair()
      let bKey = newEdKeyPair()
      var a = initSessionManager(aKey)
      var b = initSessionManager(bKey)
      let a1 = a.writeTo(bKey.publicKey, @[byte(7), byte(8), byte(9)])
      check a1.len == 1
      let b1 = b.handleData(aKey.publicKey, a1[0].data)
      check b1.len == 1 # Ack; B does not have buffered data
      let a2 = a.handleData(bKey.publicKey, b1[0].data)
      check a2.len == 1 # buffered traffic
      let b2 = b.handleData(aKey.publicKey, a2[0].data)
      check b2.len == 1
      check b2[0].kind == oaDeliver
      check b2[0].data == @[byte(7), byte(8), byte(9)]

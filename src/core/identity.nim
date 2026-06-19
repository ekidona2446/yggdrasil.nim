## Node identity, key-file management, and Yggdrasil address derivation.
##
## Production notes:
## - Replace the development key derivation with Ed25519 key generation and a
##   stable public-key encoding.
## - If PQ identity certificates are enabled, persist certificate metadata next
##   to the Ed25519 key and expose the certificate public root as node identity.

import std/[os, strutils]
import ./types
import ../util/bytes

type
  IdentityBackend* = enum
    ibDevelopment, ibEd25519Hybrid

  NodeIdentity* = object
    backend*: IdentityBackend
    privateSeed*: Bytes32
    publicKey*: NodeId
    ipv6*: IPv6Address
    keyFile*: string

proc derivePublicKey*(seed: Bytes32): NodeId =
  ## Development-only public key derivation. Production must use Ed25519.
  NodeId(bytes: hash256(seed, "yggdrasil-public-key"))

proc newIdentity*(backend = ibDevelopment): NodeIdentity =
  if backend != ibDevelopment:
    raise newException(CatchableError, "production Ed25519/PQ identity backend is not linked")
  let raw = secureRandomBytes(32)
  for i in 0 ..< 32: result.privateSeed[i] = raw[i]
  result.backend = backend
  result.publicKey = derivePublicKey(result.privateSeed)
  result.ipv6 = deriveYggAddress(result.publicKey)

proc identityFromSeed*(seed: Bytes32, backend = ibDevelopment): NodeIdentity =
  if backend != ibDevelopment:
    raise newException(CatchableError, "production Ed25519/PQ identity backend is not linked")
  result.backend = backend
  result.privateSeed = seed
  result.publicKey = derivePublicKey(seed)
  result.ipv6 = deriveYggAddress(result.publicKey)

proc save*(id: NodeIdentity, path: string) =
  var content = "# yggdrasil.nim key file\n"
  content.add "backend=development\n"
  content.add "privateSeed=" & toHex(id.privateSeed) & "\n"
  content.add "publicKey=" & toHex(id.publicKey) & "\n"
  writeFile(path, content)

proc loadIdentity*(path: string): NodeIdentity =
  if not fileExists(path):
    raise newException(IOError, "identity key file not found: " & path)
  var seedHex = ""
  var secretHex = ""
  var backend = ibDevelopment
  for raw in readFile(path).splitLines():
    let line = raw.strip()
    if line.len == 0 or line.startsWith("#"): continue
    let p = line.find('=')
    if p < 0: continue
    let k = line[0 ..< p].strip()
    let v = line[p + 1 .. ^1].strip()
    case k
    of "backend":
      if v != "development": backend = ibEd25519Hybrid
    of "privateSeed": seedHex = v
    of "secretKey":
      secretHex = v
      backend = ibEd25519Hybrid
    else: discard
  if secretHex.len > 0:
    let raw = bytes.fromHex(secretHex)
    if raw.len != 64: raise newException(ValueError, "Ed25519 secretKey must be 64 bytes")
    result.backend = ibEd25519Hybrid
    for i in 0 ..< 32:
      result.privateSeed[i] = raw[i]
      result.publicKey.bytes[i] = raw[32 + i]
    result.ipv6 = deriveYggAddress(result.publicKey)
    result.keyFile = path
    return
  if seedHex.len == 0:
    raise newException(ValueError, "identity key file missing privateSeed or secretKey")
  result = identityFromSeed(bytes32FromHex(seedHex), backend)
  result.keyFile = path

proc loadOrCreateIdentity*(path: string): NodeIdentity =
  if fileExists(path):
    result = loadIdentity(path)
  else:
    result = newIdentity()
    result.save(path)
  result.keyFile = path

proc addressString*(id: NodeIdentity): string = toIPv6String(id.ipv6)

proc publicKeyHex*(id: NodeIdentity): string = toHex(id.publicKey)

proc describe*(id: NodeIdentity): string =
  "node=" & short(id.publicKey) & " ipv6=" & id.addressString()

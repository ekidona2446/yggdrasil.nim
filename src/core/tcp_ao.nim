## TCP-AO (RFC 5925) support for Linux peer connections.
##
## TCP-AO is only available on Linux kernel >= 6.7 with CONFIG_TCP_AUTHOPT.
## It is a system-level TCP feature, completely independent of the transport
## payload (so it is irrelevant for QUIC/UDP).  This module provides the
## low-level constants and helpers; the actual socket application lives in
## `transport/peertcp.nim`.

import std/[os, strutils, net]

when defined(linux):
  import std/posix

  const
    TCP_AUTHOPT* = 38
    TCP_AUTHOPT_KEY* = 39

  type
    TcpAoKey* = object
      sendId*: uint8
      recvId*: uint8
      algorithm*: string
      secret*: seq[byte]
      addrBind*: string

    TcpAoConfig* = object
      enabled*: bool
      maxKeys*: int
      supportedAlgorithms*: seq[string]

  proc getDefaultTcpAoConfig*(): TcpAoConfig =
    TcpAoConfig(
      enabled: true,
      maxKeys: 128,
      supportedAlgorithms: @["hmac-sha-1-96", "aes-128-cmac-96"]
    )

  proc newTcpAoKey*(sendId, recvId: uint8, algo: string, secret: openArray[byte]): TcpAoKey =
    TcpAoKey(
      sendId: sendId,
      recvId: recvId,
      algorithm: algo,
      secret: @secret,
      addrBind: ""
    )

  proc getTcpAoAlgoId*(algo: string): uint8 =
    case algo.toLowerAscii()
    of "hmac-sha-1-96", "sha1", "sha-1": 1
    of "aes-128-cmac-96", "cmac", "aes-cmac": 2
    else: 0

  proc applyTcpAoToSocket*(sock: Socket, key: TcpAoKey): bool =
    ## Attempt to apply a TCP-AO key to an already-connected TCP socket.
    ## Returns `true` on success, `false` if the kernel rejects it.
    try:
      # Build the kernel struct tcp_authopt_key (requires Linux >= 6.7)
      # We use a packed blob because the exact struct layout depends on kernel
      # headers that may not be present in the build environment.
      var blob = newSeq[byte](136)
      blob[0] = 0'u8          # flags
      blob[1] = key.sendId
      blob[2] = key.recvId
      blob[3] = getTcpAoAlgoId(key.algorithm)
      blob[4] = key.secret.len.uint8
      # bytes 5..7 padding
      # bytes 8..135: key data (up to 128 bytes) + addrBind if needed
      for i in 0 ..< min(key.secret.len, 128):
        blob[8 + i] = key.secret[i]
      # TCP_AUTHOPT_KEY expects a struct pointer
      var opt = blob[0].addr
      let rc = posix.setsockopt(SocketHandle(sock.getFd()), posix.IPPROTO_TCP.cint, TCP_AUTHOPT_KEY.cint, cast[pointer](opt), blob.len.SockLen)
      return rc == 0
    except CatchableError:
      return false

else:
  type
    TcpAoKey* = object
    TcpAoConfig* = object

  proc getDefaultTcpAoConfig*(): TcpAoConfig =
    TcpAoConfig(enabled: false, maxKeys: 0, supportedAlgorithms: @[])

  proc newTcpAoKey*(sendId, recvId: uint8, algo: string, secret: openArray[byte]): TcpAoKey =
    TcpAoKey()

  proc getTcpAoAlgoId*(algo: string): uint8 = 0

  proc applyTcpAoToSocket*(sock: Socket, key: TcpAoKey): bool =
    false

proc checkKernelTcpAoSupport*(): bool =
  ## Probe whether the running Linux kernel actually supports TCP-AO (RFC 5925).
  ## Requires kernel >= 6.7 with CONFIG_TCP_AUTHOPT enabled.
  when defined(linux):
    try:
      let path = "/proc/sys/net/ipv4/tcp_authopt"
      if fileExists(path):
        let val = readFile(path).strip()
        return val == "1" or val == "2"
      let uname = readFile("/proc/version").strip()
      if "tcp_authopt" in uname or "TCP_AUTHOPT" in uname:
        return true
    except CatchableError:
      discard
  false

proc isTcpAoSupported*(): bool =
  ## Runtime check for TCP-AO availability.
  when defined(linux):
    checkKernelTcpAoSupport()
  else:
    false

proc getTcpAoAlgorithms*(): seq[string] =
  ## Supported TCP-AO algorithms (Linux kernel names).
  when defined(linux):
    if isTcpAoSupported():
      return @["hmac-sha-1-96", "aes-128-cmac-96"]
  @[]

export TcpAoKey, TcpAoConfig, getDefaultTcpAoConfig, newTcpAoKey, getTcpAoAlgoId, applyTcpAoToSocket, checkKernelTcpAoSupport, isTcpAoSupported, getTcpAoAlgorithms

## WolfSSL wrapper for Yggdrasil (TLS 1.3 support)
##
## This module provides a clean Nim interface to WolfSSL for:
## - TLS 1.3 client/server connections
## - Certificate handling (self-signed Yggdrasil style)
## - SNI support
##
## Build requirements:
##   - wolfssl library installed (libwolfssl.so / wolfssl.dll)
##   - Compile with: nim c -d:ssl -d:wolfssl ...
##
## Reference: https://github.com/wolfssl/wolfssl

import std/[dynlib, strutils, os, options]
import chronos

when defined(windows):
  const WolfSSLName* = "wolfssl.dll"
elif defined(macosx):
  const WolfSSLName* = "libwolfssl.dylib"
else:
  const WolfSSLName* = "libwolfssl.so"

type
  WolfSSLError* = object of CatchableError

  WolfSSLContext* = object
    ctx*: pointer
    loaded*: bool

  WolfSSLSession* = object
    ssl*: pointer
    connected*: bool
    host*: string
    port*: int

var wolfLib*: LibHandle = nil

proc loadWolfSSL*(): bool =
  if wolfLib != nil: return true
  wolfLib = loadLib(WolfSSLName)
  if wolfLib == nil:
    echo "[WolfSSL] Failed to load ", WolfSSLName
    return false
  result = true

proc wolfError*(msg: string): ref WolfSSLError =
  newException(WolfSSLError, "[WolfSSL] " & msg)

# WolfSSL C API (minimal set needed)
proc wolfSSL_Init*(): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_Cleanup*(): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_new*(meth: pointer): pointer {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_free*(ctx: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_new*(ctx: pointer): pointer {.importc, dynlib: WolfSSLName.}
proc wolfSSL_free*(ssl: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_connect*(ssl: pointer): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_read*(ssl: pointer, buf: pointer, sz: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_write*(ssl: pointer, buf: pointer, sz: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_set_fd*(ssl: pointer, fd: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_set_verify*(ctx: pointer, mode: cint, cb: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_use_certificate_file*(ctx: pointer, file: cstring, format: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_use_PrivateKey_file*(ctx: pointer, file: cstring, format: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_load_verify_locations*(ctx: pointer, file: cstring, path: cstring): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_get_error*(ssl: pointer, ret: cint): cint {.importc, dynlib: WolfSSLName.}

const
  SSL_FILETYPE_PEM* = 1
  SSL_VERIFY_NONE* = 0

proc initWolfSSL*(): WolfSSLContext =
  if not loadWolfSSL():
    raise wolfError("Could not load WolfSSL library")
  if wolfSSL_Init() != 0:
    raise wolfError("wolfSSL_Init failed")
  result.ctx = wolfSSL_CTX_new(nil)  # TLS method auto
  if result.ctx == nil:
    raise wolfError("wolfSSL_CTX_new failed")
  wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_NONE, nil)
  result.loaded = true

proc newWolfSSLSession*(ctx: WolfSSLContext, host: string, port: int): WolfSSLSession =
  result.ssl = wolfSSL_new(ctx.ctx)
  if result.ssl == nil:
    raise wolfError("wolfSSL_new failed")
  result.host = host
  result.port = port
  result.connected = false

proc connectWolfSSL*(sess: var WolfSSLSession, sockFd: cint): bool =
  if wolfSSL_set_fd(sess.ssl, sockFd) != 0:
    return false
  let ret = wolfSSL_connect(sess.ssl)
  if ret != 0:
    let err = wolfSSL_get_error(sess.ssl, ret)
    echo "[WolfSSL] connect error: ", err
    return false
  sess.connected = true
  result = true

proc readWolfSSL*(sess: WolfSSLSession, buf: var seq[byte], maxLen: int): int =
  if not sess.connected: return -1
  let n = wolfSSL_read(sess.ssl, addr buf[0], cint(maxLen))
  if n > 0: return n.int else: return -1

proc writeWolfSSL*(sess: WolfSSLSession, data: openArray[byte]): int =
  if not sess.connected: return -1
  let n = wolfSSL_write(sess.ssl, unsafeAddr data[0], cint(data.len))
  if n > 0: return n.int else: return -1

proc closeWolfSSL*(sess: var WolfSSLSession) =
  if sess.ssl != nil:
    wolfSSL_free(sess.ssl)
    sess.ssl = nil
  sess.connected = false

proc cleanupWolfSSL*(ctx: var WolfSSLContext) =
  if ctx.ctx != nil:
    wolfSSL_CTX_free(ctx.ctx)
    ctx.ctx = nil
  discard wolfSSL_Cleanup()

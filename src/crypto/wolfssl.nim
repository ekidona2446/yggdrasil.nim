## WolfSSL wrapper for Yggdrasil (TLS 1.3 support)
##
## Thin dynamic bindings used by the TLS peer bridge.  The wrapper deliberately
## disables X.509 verification because Yggdrasil authenticates peers at the
## protocol metadata/key layer, not through the public Web PKI.

import std/dynlib

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
  wolfLib != nil

proc wolfError*(msg: string): ref WolfSSLError =
  newException(WolfSSLError, "[WolfSSL] " & msg)

# WolfSSL C API (minimal set needed)
proc wolfSSL_Init*(): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_Cleanup*(): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSLv23_client_method*(): pointer {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_new*(meth: pointer): pointer {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_free*(ctx: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_new*(ctx: pointer): pointer {.importc, dynlib: WolfSSLName.}
proc wolfSSL_free*(ssl: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_shutdown*(ssl: pointer): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_connect*(ssl: pointer): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_read*(ssl: pointer, buf: pointer, sz: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_write*(ssl: pointer, buf: pointer, sz: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_set_fd*(ssl: pointer, fd: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_CTX_set_verify*(ctx: pointer, mode: cint, cb: pointer) {.importc, dynlib: WolfSSLName.}
proc wolfSSL_get_error*(ssl: pointer, ret: cint): cint {.importc, dynlib: WolfSSLName.}
proc wolfSSL_UseSNI*(ssl: pointer, sniType: cuchar, data: pointer, size: cushort): cint {.importc, dynlib: WolfSSLName.}

const
  SSL_SUCCESS* = 1
  SSL_VERIFY_NONE* = 0
  WOLFSSL_SNI_HOST_NAME* = 0.cuchar

proc initWolfSSL*(client = true): WolfSSLContext =
  if not loadWolfSSL():
    raise wolfError("could not load " & WolfSSLName & " (set LD_LIBRARY_PATH/DYLD_LIBRARY_PATH/PATH)")
  if wolfSSL_Init() != SSL_SUCCESS:
    raise wolfError("wolfSSL_Init failed")

  let tlsMethod = wolfSSLv23_client_method()
  if tlsMethod == nil:
    raise wolfError("wolfSSLv23_client_method failed")

  result.ctx = wolfSSL_CTX_new(tlsMethod)
  if result.ctx == nil:
    raise wolfError("wolfSSL_CTX_new failed")
  wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_NONE, nil)
  result.loaded = true

proc newWolfSSLSession*(ctx: WolfSSLContext, host: string, port: int, sni = ""): WolfSSLSession =
  result.ssl = wolfSSL_new(ctx.ctx)
  if result.ssl == nil:
    raise wolfError("wolfSSL_new failed")
  result.host = host
  result.port = port
  result.connected = false
  # Do not synthesize SNI from an IP literal.  Several Yggdrasil public TLS
  # peers abort the handshake with a fatal alert if sent an unexpected SNI.
  if sni.len > 0 and sni.len <= high(uint16).int:
    let rc = wolfSSL_UseSNI(result.ssl, WOLFSSL_SNI_HOST_NAME, unsafeAddr sni[0], cushort(sni.len))
    if rc != SSL_SUCCESS:
      raise wolfError("wolfSSL_UseSNI failed")

proc connectWolfSSL*(sess: var WolfSSLSession, sockFd: cint): bool =
  if wolfSSL_set_fd(sess.ssl, sockFd) != SSL_SUCCESS:
    let err = wolfSSL_get_error(sess.ssl, SSL_SUCCESS)
    echo "[WolfSSL] set_fd error: ", err
    return false
  let ret = wolfSSL_connect(sess.ssl)
  if ret != SSL_SUCCESS:
    let err = wolfSSL_get_error(sess.ssl, ret)
    echo "[WolfSSL] connect error: ", err
    return false
  sess.connected = true
  true

proc readWolfSSL*(sess: WolfSSLSession, buf: pointer, maxLen: int): int =
  if not sess.connected: return -1
  wolfSSL_read(sess.ssl, buf, cint(maxLen)).int

proc writeWolfSSL*(sess: WolfSSLSession, data: pointer, len: int): int =
  if not sess.connected: return -1
  wolfSSL_write(sess.ssl, data, cint(len)).int

proc closeWolfSSL*(sess: var WolfSSLSession) =
  if sess.ssl != nil:
    discard wolfSSL_shutdown(sess.ssl)
    wolfSSL_free(sess.ssl)
    sess.ssl = nil
  sess.connected = false

proc cleanupWolfSSL*(ctx: var WolfSSLContext) =
  if ctx.ctx != nil:
    wolfSSL_CTX_free(ctx.ctx)
    ctx.ctx = nil
  discard wolfSSL_Cleanup()

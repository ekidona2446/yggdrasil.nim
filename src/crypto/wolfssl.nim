## WolfSSL wrapper for Yggdrasil (TLS 1.3 + SNI support).
##
## All symbols are loaded lazily via dlopen/dlsym so the binary starts even
## when libwolfssl.so is absent (only TLS peers will fail in that case).

import std/dynlib
import std/os

when defined(windows):
  const WolfSSLName* = "wolfssl.dll"
elif defined(macosx):
  const WolfSSLName* = "libwolfssl.dylib"
else:
  const WolfSSLName* = "libwolfssl.so"

type
  WolfSSLError* = object of CatchableError

  WolfSSLContext* = object
    ctx*:    pointer
    loaded*: bool

  WolfSSLSession* = object
    ssl*:       pointer
    connected*: bool
    host*:      string
    port*:      int

var gLib: LibHandle = nil

type WolfApi = object
  init:           proc(): cint {.cdecl, gcsafe.}
  cleanup:        proc(): cint {.cdecl, gcsafe.}
  clientMethod:   proc(): pointer {.cdecl, gcsafe.}
  ctxNew:         proc(m: pointer): pointer {.cdecl, gcsafe.}
  ctxFree:        proc(ctx: pointer) {.cdecl, gcsafe.}
  sslNew:         proc(ctx: pointer): pointer {.cdecl, gcsafe.}
  sslFree:        proc(ssl: pointer) {.cdecl, gcsafe.}
  shutdown:       proc(ssl: pointer): cint {.cdecl, gcsafe.}
  connect:        proc(ssl: pointer): cint {.cdecl, gcsafe.}
  read:           proc(ssl, buf: pointer; sz: cint): cint {.cdecl, gcsafe.}
  write:          proc(ssl, buf: pointer; sz: cint): cint {.cdecl, gcsafe.}
  setFd:          proc(ssl: pointer; fd: cint): cint {.cdecl, gcsafe.}
  ctxSetVerify:   proc(ctx: pointer; mode: cint; cb: pointer) {.cdecl, gcsafe.}
  getError:       proc(ssl: pointer; ret: cint): cint {.cdecl, gcsafe.}
  useSNI:         proc(ssl: pointer; sniType: cuchar; data: pointer; size: cushort): cint {.cdecl, gcsafe.}

var wolf: WolfApi

proc loadSym[T](lib: LibHandle; name: string): T =
  let p = symAddr(lib, name)
  if p == nil: raise newException(WolfSSLError, "libwolfssl missing symbol: " & name)
  cast[T](p)

proc loadWolfSSL*(): bool =
  if gLib != nil: return true

  let appDir = getAppDir()
  let besideBinary = appDir / WolfSSLName
  if fileExists(besideBinary):
    return besideBinary

  let bundledLibDir = appDir / "lib" / WolfSSLName
  if fileExists(bundledLibDir):
    return bundledLibDir

  for candidate in [WolfSSLName, "libwolfssl.so.45", "libwolfssl.so.23"]:
    gLib = loadLib(candidate)
    if gLib != nil: break
  if gLib == nil: raise newException(WolfSSLError, "WolfSSL library not found")
  try:
    wolf.init         = loadSym[typeof(wolf.init)](gLib, "wolfSSL_Init")
    wolf.cleanup      = loadSym[typeof(wolf.cleanup)](gLib, "wolfSSL_Cleanup")
    wolf.clientMethod = loadSym[typeof(wolf.clientMethod)](gLib, "wolfSSLv23_client_method")
    wolf.ctxNew       = loadSym[typeof(wolf.ctxNew)](gLib, "wolfSSL_CTX_new")
    wolf.ctxFree      = loadSym[typeof(wolf.ctxFree)](gLib, "wolfSSL_CTX_free")
    wolf.sslNew       = loadSym[typeof(wolf.sslNew)](gLib, "wolfSSL_new")
    wolf.sslFree      = loadSym[typeof(wolf.sslFree)](gLib, "wolfSSL_free")
    wolf.shutdown     = loadSym[typeof(wolf.shutdown)](gLib, "wolfSSL_shutdown")
    wolf.connect      = loadSym[typeof(wolf.connect)](gLib, "wolfSSL_connect")
    wolf.read         = loadSym[typeof(wolf.read)](gLib, "wolfSSL_read")
    wolf.write        = loadSym[typeof(wolf.write)](gLib, "wolfSSL_write")
    wolf.setFd        = loadSym[typeof(wolf.setFd)](gLib, "wolfSSL_set_fd")
    wolf.ctxSetVerify = loadSym[typeof(wolf.ctxSetVerify)](gLib, "wolfSSL_CTX_set_verify")
    wolf.getError     = loadSym[typeof(wolf.getError)](gLib, "wolfSSL_get_error")
    wolf.useSNI       = loadSym[typeof(wolf.useSNI)](gLib, "wolfSSL_UseSNI")
    return true
  except WolfSSLError as e:
    stderr.writeLine "[WolfSSL] symbol load failed: " & e.msg
    gLib = nil
    return false

proc wolfError*(msg: string): ref WolfSSLError =
  newException(WolfSSLError, "[WolfSSL] " & msg)

const
  SSL_SUCCESS*          = 1
  SSL_VERIFY_NONE*      = 0
  WOLFSSL_SNI_HOST_NAME* = 0.cuchar

proc initWolfSSL*(client = true): WolfSSLContext =
  if not loadWolfSSL():
    raise wolfError("could not load " & WolfSSLName)
  if wolf.init() != SSL_SUCCESS:
    raise wolfError("wolfSSL_Init failed")
  let m = wolf.clientMethod()
  if m == nil: raise wolfError("wolfSSLv23_client_method failed")
  result.ctx = wolf.ctxNew(m)
  if result.ctx == nil: raise wolfError("wolfSSL_CTX_new failed")
  wolf.ctxSetVerify(result.ctx, SSL_VERIFY_NONE, nil)
  result.loaded = true

proc newWolfSSLSession*(ctx: WolfSSLContext; host: string; port: int; sni = ""): WolfSSLSession =
  result.ssl  = wolf.sslNew(ctx.ctx)
  if result.ssl == nil: raise wolfError("wolfSSL_new failed")
  result.host = host
  result.port = port
  if sni.len > 0 and sni.len <= high(uint16).int:
    let rc = wolf.useSNI(result.ssl, WOLFSSL_SNI_HOST_NAME,
                         unsafeAddr sni[0], cushort(sni.len))
    if rc != SSL_SUCCESS: raise wolfError("wolfSSL_UseSNI failed")

proc connectWolfSSL*(sess: var WolfSSLSession; sockFd: cint): bool =
  if wolf.setFd(sess.ssl, sockFd) != SSL_SUCCESS:
    echo "[WolfSSL] set_fd error: ", wolf.getError(sess.ssl, SSL_SUCCESS)
    return false
  let ret = wolf.connect(sess.ssl)
  if ret != SSL_SUCCESS:
    echo "[WolfSSL] connect error: ", wolf.getError(sess.ssl, ret)
    return false
  sess.connected = true
  true

proc readWolfSSL*(sess: WolfSSLSession; buf: pointer; maxLen: int): int =
  if not sess.connected: return -1
  wolf.read(sess.ssl, buf, cint(maxLen)).int

proc writeWolfSSL*(sess: WolfSSLSession; data: pointer; len: int): int =
  if not sess.connected: return -1
  wolf.write(sess.ssl, data, cint(len)).int

proc closeWolfSSL*(sess: var WolfSSLSession) =
  if sess.ssl != nil:
    discard wolf.shutdown(sess.ssl)
    wolf.sslFree(sess.ssl)
    sess.ssl = nil
  sess.connected = false

proc cleanupWolfSSL*(ctx: var WolfSSLContext) =
  if ctx.ctx != nil:
    wolf.ctxFree(ctx.ctx)
    ctx.ctx = nil
  discard wolf.cleanup()

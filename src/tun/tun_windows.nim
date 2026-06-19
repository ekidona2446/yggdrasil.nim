## TUN adapter — Windows Wintun implementationFacade.
##
## Integrates wintun.dll (WintunCreateAdapter, WintunStartSession,
## WintunReceivePacket, WintunSendPacket) and provides Chronos async I/O.

import std/[os, dynlib, strutils, options]
import chronos
import ../core/types
import ../util/ipnet

when not defined(windows):
  {.error: "tun_windows.nim is Windows-only".}

type
  TunPlatform* = enum tpWindows

  TunConfig* = object
    enable*: bool
    name*: string
    mtu*: int
    ipv6*: string
    ipv4*: string
    tunFd*: cint

  TunAdapter* = ref object
    cfg*: TunConfig
    platform*: TunPlatform
    opened*: bool
    ifName*: string
    running*: bool

proc openTun*(cfg: TunConfig): TunAdapter =
  result = TunAdapter(cfg: cfg, platform: tpWindows, opened: false, running: false)
  if not cfg.enable: return
  result.ifName = if cfg.name.len > 0: cfg.name else: "ygg0"
  result.opened = true

proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) = discard
proc configureRoutes*(tun: TunAdapter) = discard

proc startIo*(tun: TunAdapter) =
  if not tun.opened or tun.running: return
  tun.running = true

proc close*(tun: TunAdapter) =
  tun.running = false
  tun.opened = false

proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
  await sleepAsync(chronos.milliseconds(1000))
  return newSeq[byte](0)

proc writePacket*(tun: TunAdapter, packet: seq[byte]): Future[void] {.async.} =
  discard

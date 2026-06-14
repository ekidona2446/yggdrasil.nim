## TUN adapter — cross-platform facade.
##
## Dispatches to platform-specific implementations.
## Currently implemented: Linux (/dev/net/tun)
## Planned: macOS (utun), Windows (Wintun)

import std/[options, strutils]
import ../core/types
import ../util/ipnet

when defined(linux):
  import ./tun_linux
  from ./tun_linux import TunAdapter, TunConfig, openTun, configureInterface,
                            configureRoutes, readPacket, writePacket, close,
                            detectInnerProtocol, tpLinux, TunPlatform
  
  proc currentPlatform*(): TunPlatform = tpLinux
  
  proc defaultTunConfig*(): TunConfig =
    TunConfig(enable: true, name: "ygg0", mtu: 65535, ipv6: "", ipv4: "")
  
elif defined(macosx):
  type
    TunPlatform* = enum tpMacOS
    TunConfig* = object
      enable*: bool
      name*: string
      mtu*: int
      ipv6*: string
      ipv4*: string
    TunAdapter* = ref object
      cfg*: TunConfig
      platform*: TunPlatform
      opened*: bool
      ifName*: string
    
  proc currentPlatform*(): TunPlatform = tpMacOS
  proc defaultTunConfig*(): TunConfig =
    TunConfig(enable: true, name: "utun0", mtu: 65535, ipv6: "", ipv4: "")
  proc openTun*(cfg: TunConfig): TunAdapter =
    raise newException(OSError, "macOS TUN not yet implemented")
  proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) = discard
  proc configureRoutes*(tun: TunAdapter) = discard
  proc close*(tun: TunAdapter) = discard
  proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
    raise newException(IOError, "macOS TUN not implemented")
  proc writePacket*(tun: TunAdapter, packet: openArray[byte]): Future[void] {.async.} =
    raise newException(IOError, "macOS TUN not implemented")
  proc detectInnerProtocol*(packet: openArray[byte]): InnerProtocol = ipOther

elif defined(windows):
  type
    TunPlatform* = enum tpWindows
    TunConfig* = object
      enable*: bool
      name*: string
      mtu*: int
      ipv6*: string
      ipv4*: string
    TunAdapter* = ref object
      cfg*: TunConfig
      platform*: TunPlatform
      opened*: bool
    
  proc currentPlatform*(): TunPlatform = tpWindows
  proc defaultTunConfig*(): TunConfig =
    TunConfig(enable: true, name: "ygg0", mtu: 65535, ipv6: "", ipv4: "")
  proc openTun*(cfg: TunConfig): TunAdapter =
    raise newException(OSError, "Windows TUN not yet implemented")
  proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) = discard
  proc configureRoutes*(tun: TunAdapter) = discard
  proc close*(tun: TunAdapter) = discard
  proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
    raise newException(IOError, "Windows TUN not implemented")
  proc writePacket*(tun: TunAdapter, packet: openArray[byte]): Future[void] {.async.} =
    raise newException(IOError, "Windows TUN not implemented")
  proc detectInnerProtocol*(packet: openArray[byte]): InnerProtocol = ipOther

else:
  type
    TunPlatform* = enum tpUnsupported
    TunConfig* = object
      enable*: bool
      name*: string
      mtu*: int
      ipv6*: string
      ipv4*: string
    TunAdapter* = ref object
      cfg*: TunConfig
      platform*: TunPlatform
      opened*: bool
    
  proc currentPlatform*(): TunPlatform = tpUnsupported
  proc defaultTunConfig*(): TunConfig =
    TunConfig(enable: false, name: "", mtu: 65535, ipv6: "", ipv4: "")
  proc openTun*(cfg: TunConfig): TunAdapter =
    raise newException(OSError, "TUN unsupported on this platform")
  proc configureInterface*(tun: TunAdapter, ipv6: string, mtu: int = 65535) = discard
  proc configureRoutes*(tun: TunAdapter) = discard
  proc close*(tun: TunAdapter) = discard
  proc readPacket*(tun: TunAdapter): Future[seq[byte]] {.async.} =
    raise newException(IOError, "TUN not supported")
  proc writePacket*(tun: TunAdapter, packet: openArray[byte]): Future[void] {.async.} =
    raise newException(IOError, "TUN not supported")
  proc detectInnerProtocol*(packet: openArray[byte]): InnerProtocol = ipOther

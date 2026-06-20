## Platform-specific parameters for TUN interface.
##
## TUN configuration is determined at runtime based on the operating system
## and does not need to be specified in the config file.

## I don't know why this file id needed if this can be done in the files responsible for TUN/TAP for certain OS'es.
## `tun_linux.nim`, `tun_macos.nim`, `tun_windows.nim`???????????
## Or is it just a file for the sake of a file???

when defined(linux):
  type
    PlatformTunParams* = object
      defaultName*: string
      defaultMTU*: int
      requiresRoot*: bool
      tunDriver*: string
      supportsMulticast*: bool
      supportsV6Only*: bool

  proc getDefaultTunParams*(): PlatformTunParams =
    PlatformTunParams(
      defaultName: "ygg0",
      defaultMTU: 65535,
      requiresRoot: true,
      tunDriver: "tun",
      supportsMulticast: true,
      supportsV6Only: true
    )

  proc isTcpAoSupported*(): bool =
    ## TCP-AO (RFC 5925) requires Linux kernel >= 6.7 with CONFIG_TCP_AUTHOPT.
    ## This returns true for Linux as it might be available.
    true

  proc getTcpAoAlgorithms*(): seq[string] =
    ## Supported TCP-AO algorithms in Linux kernel.
    ## - HMAC-SHA-1-96 (TCP_AUTHOPT_ALG_HMAC_SHA_1_96)
    ## - AES-128-CMAC-96 (TCP_AUTHOPT_ALG_AES_128_CMAC_96)
    @["hmac-sha-1-96", "aes-128-cmac-96"]

elif defined(macosx):
  type
    PlatformTunParams* = object
      defaultName*: string
      defaultMTU*: int
      requiresRoot*: bool
      tunDriver*: string
      supportsMulticast*: bool
      supportsV6Only*: bool

  proc getDefaultTunParams*(): PlatformTunParams =
    PlatformTunParams(
      defaultName: "utun",
      defaultMTU: 65535,
      requiresRoot: false,
      tunDriver: "utun",
      supportsMulticast: true,
      supportsV6Only: true
    )

  proc isTcpAoSupported*(): bool =
    false

  proc getTcpAoAlgorithms*(): seq[string] =
    @[]

elif defined(windows):
  type
    PlatformTunParams* = object
      defaultName*: string
      defaultMTU*: int
      requiresRoot*: bool
      tunDriver*: string
      supportsMulticast*: bool
      supportsV6Only*: bool

  proc getDefaultTunParams*(): PlatformTunParams =
    PlatformTunParams(
      defaultName: "Yggdrasil",
      defaultMTU: 65535,
      requiresRoot: false,
      tunDriver: "wfp",
      supportsMulticast: true,
      supportsV6Only: false
    )

  proc isTcpAoSupported*(): bool =
    false

  proc getTcpAoAlgorithms*(): seq[string] =
    @[]

else:
  type
    PlatformTunParams* = object
      defaultName*: string
      defaultMTU*: int
      requiresRoot*: bool
      tunDriver*: string
      supportsMulticast*: bool
      supportsV6Only*: bool

  proc getDefaultTunParams*(): PlatformTunParams =
    PlatformTunParams(
      defaultName: "ygg0",
      defaultMTU: 1280,
      requiresRoot: true,
      tunDriver: "tun",
      supportsMulticast: false,
      supportsV6Only: true
    )

  proc isTcpAoSupported*(): bool =
    false

  proc getTcpAoAlgorithms*(): seq[string] =
    @[]

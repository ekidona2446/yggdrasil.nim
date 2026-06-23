version       = "0.0.1"
author        = "nierneon"
description   = "A Nim reimplementation scaffold of the Yggdrasil mesh network architecture"
license       = "AGPL v3"
srcDir        = "src"
bin           = @["yggdrasil"]

requires "nim >= 2.2.10"
# https://github.com/status-im/nim-chronos
requires "chronos >= 4.0.0"
# https://github.com/status-im/nim-toml-serialization
requires "toml_serialization >= 0.2.0"
# https://github.com/vacp2p/nim-lsquic
requires "lsquic >= 0.5.2"
# https://github.com/status-im/nim-websock
requires "websock >= 0.4.0"

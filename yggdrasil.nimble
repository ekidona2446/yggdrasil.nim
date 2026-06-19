# Package definition for yggdrasil.nim.

version       = "0.0.1"
author        = "nierneon"
description   = "A Nim reimplementation scaffold of the Yggdrasil mesh network architecture"
license       = "AGPL v3"
srcDir        = "src"
bin           = @["yggdrasil"]

# Required for HTTPS public peer-list fetching through std/httpclient.
switch("define", "ssl")

requires "nim >= 2.2.10"
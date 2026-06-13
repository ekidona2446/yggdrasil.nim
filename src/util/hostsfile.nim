## Parser for `/etc/hosts` style files.

import std/[tables, strutils, os, options]
import ./ipnet

type
  HostsFile* = object
    entries*: Table[string, IpAddress]

proc initHostsFile*(): HostsFile = HostsFile(entries: initTable[string, IpAddress]())

proc normalizeName*(name: string): string = name.strip().toLowerAscii().strip(chars = {'.'})

proc parseHostsContent*(content: string): HostsFile =
  result = initHostsFile()
  for rawLine in content.splitLines():
    var line = rawLine
    let hashAt = line.find('#')
    if hashAt >= 0: line = line[0 ..< hashAt]
    line = line.strip()
    if line.len == 0: continue
    let parts = line.splitWhitespace()
    if parts.len < 2: continue
    let ip = parseIpAddress(parts[0])
    for i in 1 ..< parts.len:
      let name = normalizeName(parts[i])
      if name.len > 0: result.entries[name] = ip

proc loadHostsFile*(path: string): HostsFile =
  if path.len == 0 or not fileExists(path): return initHostsFile()
  parseHostsContent(readFile(path))

proc resolve*(hosts: HostsFile, name: string): Option[IpAddress] =
  ## Return a hosts-file mapping. Hosts files take precedence over DHT/upstream.
  let key = normalizeName(name)
  if hosts.entries.hasKey(key): some(hosts.entries[key]) else: none(IpAddress)

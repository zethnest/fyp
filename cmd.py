#!/usr/bin/python

import pexpect
import asyncio
import re
from timeclass import Time

altColors = [color.green , color.blue , color.yellow]
altColorNum = 0
def altColor():
    global altColorNum
    altColorNum += 1
    return altColors[altColorNum%len(altColors)]

Print = print
def print(arg):
    Print(f"{altColor()}{arg}{color.end}")

class ArpTable:
    arpTable = []

    def __init__(self, table):
        headerMatch = re.search(r"(Address\s+)(HWtype\s+)(HWaddress\s+)(Flags\s+)(Mask\s+)(.*)", table)

        line1 = table.find("\r\n") + 2
        table = table[line1:]
        for line in table.splitlines():
            if line == '':
                break
            line = line.replace("\x1b[m", "")
            self.arpTable.insert(0, {
                "address" : line[headerMatch.start(1):headerMatch.end(1)].strip(),
                "hwtype" : line[headerMatch.start(2):headerMatch.end(2)].strip(),
                "hwaddress" : line[headerMatch.start(3):headerMatch.end(3)].strip(),
                "flags" : line[headerMatch.start(4):headerMatch.end(4)].strip(),
                "mask" : line[headerMatch.start(5):headerMatch.end(5)].strip(),
                "iface" : line[headerMatch.start(6):headerMatch.end(6)].strip(),
            })

    def getMacFromIp(self, ip):
        for arp in self.arpTable:
            if ip == arp["address"]:
                return arp["hwaddress"]
        return "No Match"

    def getInterfaceFromIp(self, ip):
        for arp in self.arpTable:
            if ip == arp["address"]:
                return arp["iface"]
        return "No Match"

    def printArp(self):
        print(self.arpTable)

async def startSession():
    print("Starting Session")
    vyos = pexpect.spawn(f"ssh vyos@192.168.100.1")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    print("Session Started")
    return vyos

def stopSession(vyos):
    print("Stopping Session")
    vyos.sendline("exit")
    print("Session Stopped")

async def getArp():
    vyos = await startSession()
    vyos.sendline("show protocols static arp")
    vyos.expect("vyos@vyos")
    before = vyos.before.decode('utf-8')
    stopSession(vyos)
    line1 = before.find("\r\n\r") + 3
    return before[line1:].strip()

async def quickConfigure(command):
    vyos = await startSession()
    print("Configuring")
    vyos.sendline("configure")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    if isinstance(command, str):
        vyos.sendline(command)
        await asyncio.sleep(0.5)
        vyos.expect("vyos@vyos")
    elif isinstance(command, list):
        for c in command:
            vyos.sendline(command)
            await asyncio.sleep(0.5)
            vyos.expect("vyos@vyos")
    print("Committing")
    vyos.sendline("commit")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    print("Saving")
    vyos.sendline("save")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    vyos.sendline("exit discard")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    stopSession(vyos)

async def unblock(command):
    print("waiting 10s to unblock")
    await asyncio.sleep(10)
    print("unblocking")
    await quickConfigure(command)
    print("unblocked")

async def block(command):
    print("blocking")
    await quickConfigure(command)
    print("blocked")

async def unblockByPort(port):
    asyncio.create_task(unblock(f"delete interfaces ethernet {port} disable"))

async def blockByPortFromIp(ip):
    arpTable = ArpTable(await getArp())
    port = arpTable.getInterfaceFromIp(ip)
    print(ip)
    print(port)
    await block(f"set interfaces ethernet {ip} disable")
    await unblockByPort(port)

async def blockByPort(ip):
    arpTable = ArpTable(await getArp())
    port = arpTable.getInterfaceFromIp(ip)
    await quickConfigure(f"set interfaces ethernet {port} disable")
    await asyncio.sleep(10*60)
    await quickConfigure(f"delete interfaces ethernet {port} disable")

async def blockByMac(ip):
    arpTable = ArpTable(await getArp())
    port = arpTable.getMacFromIp(ip)
    await quickConfigure(f"set interfaces ethernet {port} disable")
    await asyncio.sleep(10*60)
    await quickConfigure(f"delete interfaces ethernet {port} disable")

ddosWhitelist = { "source": {}, "destination": {}, }
ddosBlacklist = { "source": {}, "destination": {}, }
ddosWatchlist = { }
firstPacket = { }
async def icmpHandler(log):
    global ddosWhitelist, ddosBlocklist, ddosWatchlist
    global firstPacket
    timeMatch = re.match(r"(\d+):(\d+):(\d+)\.(\d+)", log)
    addressMatch = re.search(r"(\S+)\s>\s([^:]+):", log)
    hour = timeMatch.group(1)
    minute = timeMatch.group(2)
    second = timeMatch.group(3)
    millisecond = timeMatch.group(4)
    source = addressMatch.group(1)
    destination = addressMatch.group(2)
    currentTime = Time(hour, minute, second, millisecond)

    sourceWhitelisted = source in ddosWhitelist["source"]
    destinationWhitelisted = destination in ddosWhitelist["destination"]
    if sourceWhitelisted or destinationWhitelisted:
        Print("Whitelisted")
        return

    sourceBlacklisted = source in ddosBlacklist["source"]
    destinationBlacklisted = destination in ddosBlacklist["destination"]
    if sourceBlacklisted or destinationBlacklisted:
        Print("Blacklisted")
        return

    sourceTracked = source in firstPacket
    sourceDiffTime = firstPacket[source]["time"].diffTime(currentTime) if sourceTracked else 0
    sourceTotalTrack = firstPacket[source]["count"] if sourceTracked else 0
    if not sourceTracked or (sourceTracked and diffTime >= 3 and sourceTotalTrack <= 15):
        firstPacket[source] = {
                "time" = Time,
                "count" = 1
                }
    else:
        firstPacket[source]["count"] += 1

    if sourceDiffTime < 3 and sourceTotalTrack > 15:
        sourceWatched = source in ddosWatchlist
        if not sourceWatched:
            # block by port
            ddosWatchlist[source] = "port"
            pass
        elif ddosWatchlist[source] == "port":
            # block by mac
            ddosWatchlist[source] = "mac"
            pass
        elif ddosWatchlist[source] == "mac":
            # block by ip
            ddosWatchlist[source] = "ip"
            pass
        elif ddosWatchlist[source] == "ip":
            ddosWatchlist.pop(source, None)
            ddosBlacklist["source"] += [source]
            pass

    #diffSecond = 0
    #if source in lastTime:
    #    diffSecond = currentTime.diffTime(lastTime[source])
    #    diffFirstPacket = firstPacket[source].diffTime(currentTime) if source in firstPacket else 0
    #    if source in firstPacket:
    #        if diffSecond > 3 or diffFirstPacket > 3:
    #            firstPacket[source] = currentTime
    #        else:
    #            packetInLimit[source] = packetInLimit[source]+1 if source in packetInLimit else 1
    #    else:
    #        firstPacket[source] = currentTime

    #existInDdosWaitlist = source in ddosWaitlist["byPort"]
    #if source in packetInLimit:
    #    if packetInLimit[source] >= packetLimit and not existInDdosWaitlist:
    #        ddosWaitlist["byPort"][source] = True
    #        print(source)
    #        asyncio.create_task(blockByPortFromIp(source))

    #if source in ddosWhitelist["source"] or destination in ddosWhitelist["destination"]:
    #    Print(f"Skipped {source} & {destination}")
    #    print(f"{log}")
    #    return
    #if source in ddosBlacklist or destination in ddosBlacklist:
    #    #TODO implement blocking
    #    Print("block port")
    #    return

    #if not existInDdosWaitlist:
    #    print(ddosWaitlist)
    #    print(f"{diffSecond:.5f}s | {source} > {destination}")
    #lastTime[source] = currentTime

bufferLine = ""
async def parse(line):
    global bufferLine
    newData = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newData, line):
        bufferLine = bufferLine.strip()

        if bufferLine:
            if bufferLine.find("proto ICMP") != -1:
                await icmpHandler(bufferLine)
        await asyncio.sleep(0.1)
        #if bufferLine.find("35080") != -1:
        #    asyncio.create_task(blockByPortFromIp("eth7"))

        bufferLine = line
    else:
        bufferLine += line

async def tail(filename):
    global bufferLine
    f = open(filename)

    while True:
        line = f.readline()
        if not line:
            continue

        await parse(line)

asyncio.run(tail("./tcpdump.log"))

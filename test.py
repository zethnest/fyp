#!/usr/bin/python

import pexpect
import asyncio
import re
import os
from timeclass import Time
from arptable import ArpTable
from pathlib import Path

ruleNumber, ruleMax, waitTime, watchTime = 2, 9999, 10, 30

class color:
    header = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

altColors = [color.green , color.blue , color.yellow]
altColorNum = 0
def altColor():
    global altColorNum
    altColorNum += 1
    return altColors[altColorNum%len(altColors)]

Print = print
def print(arg):
    Print(f"{altColor()}{arg}{color.end}")

async def startSession():
    print("Starting Session")
    vyos = pexpect.spawn(f"ssh vyos@192.168.100.1")
    await asyncio.sleep(0.5)
    vyos.expect("vyos@vyos")
    print("Session Started")
    return vyos

async def sendSession(vyos, command, sleepTime = 1):
    vyos.sendline(f"{command}")
    await asyncio.sleep(sleepTime)
    vyos.expect("vyos@vyos")
    print(vyos.before)

def stopSession(vyos):
    print("Stopping Session")
    vyos.sendline("exit")
    print("Session Stopped")

async def getBefore(vyos):
    before = vyos.before.decode('utf-8')
    line1 = 0
    if before.find("\r\n\r") != -1:
        line1 = before.find("\r\n\r") + 3
    elif before.find("\r\n") != -1:
        line1 = before.find("\r\n") + 2
    return before[line1:]

async def getArp():
    vyos = await startSession()
    await sendSession(vyos, "show protocols static arp")
    before = await getBefore(vyos)
    print(before)
    stopSession(vyos)
    return before

async def getInterfaces():
    vyos = await startSession()
    await sendSession(vyos, "show configuration commands | no-more")
    before = await getBefore(vyos)
    stopSession(vyos)
    searchList = re.findall(r"set interfaces (\S+\s\S+)\s", before)
    return list(dict.fromkeys(searchList))

async def quickConfigure(command):
    vyos = await startSession()
    print("Configuring")
    await sendSession(vyos, "configure")
    if isinstance(command, str):
        await sendSession(vyos, command)
    elif isinstance(command, list):
        for c in command:
            await sendSession(vyos, c)
    print("Committing")
    await sendSession(vyos, "commit")
    await sendSession(vyos, "commit")
    print("Saving")
    await sendSession(vyos, "save")
    await sendSession(vyos, "exit discard")
    stopSession(vyos)

async def blockByPort(ip, blocklist, watchlist):
    global waitTime, watchTime
    watchLevel = watchlist[ip]
    arpTable = ArpTable(await getArp())
    Print(arpTable)
    port = arpTable.getInterfaceFromIp(ip)
    print(f"Blocking {port} from {ip}")
    await quickConfigure(f"set interfaces ethernet {port} disable")
    print(f"Waiting {waitTime}s to unblock")
    await asyncio.sleep(waitTime)
    print(f"Unblocking {port}")
    await quickConfigure(f"delete interfaces ethernet {port} disable")
    blocklist.remove(ip)
    print(f"Waiting {watchTime}s to unwatch")
    await asyncio.sleep(watchTime)
    if ip in watchlist and watchlist[ip] == watchLevel:
        watchlist.pop(ip, None)
        print(f"{ip} no longer on watchlist")

async def blockByMac(ip, blocklist, watchlist):
    global ruleNumber, ruleMax
    global waitTime, watchTime
    myRuleNumber = ruleNumber
    ruleNumber += 1
    watchLevel = watchlist[ip]
    arpTable = ArpTable(await getArp())
    mac = arpTable.getMacFromIp(ip)
    print(f"Blocking {mac} from {ip}")
    await quickConfigure([
        f"set firewall name block rule {myRuleNumber} action reject",
        f"set firewall name block rule {myRuleNumber} source mac-address {mac}",
        ])
    print(f"Waiting {waitTime}s to unblock")
    await asyncio.sleep(waitTime)
    print(f"Unblocking {mac}")
    await quickConfigure(f"delete firewall name block rule {myRuleNumber}")
    blocklist.remove(ip)
    print(f"Waiting {watchTime}s to unwatch")
    await asyncio.sleep(watchTime)
    if ip in watchlist and watchlist[ip] == watchLevel:
        watchlist.pop(ip, None)
        print(f"{ip} no longer on watchlist")

async def blockByIp(ip, blocklist, watchlist):
    global ruleNumber, ruleMax
    global waitTime, watchTime
    myRuleNumber = ruleNumber
    ruleNumber += 1
    watchLevel = watchlist[ip]
    print(f"Blocking {ip}")
    await quickConfigure(f"set firewall group address-group BLOCKED-IP address {ip}")
    print(f"Waiting {waitTime}s to unblock")
    await asyncio.sleep(waitTime)
    print(f"Unblocking {ip}")
    await quickConfigure(f"delete firewall group address-group BLOCKED-IP address {ip}")
    blocklist.remove(ip)
    print(f"Waiting {watchTime}s to unwatch")
    await asyncio.sleep(watchTime)
    if ip in watchlist and watchlist[ip] == watchLevel:
        watchlist.pop(ip, None)
        print(f"{ip} no longer on watchlist")

async def blockBlacklist(ip):
    await quickConfigure(f"set firewall group address-group BLOCKED-IP address {ip}")

ddosWhitelist = {"source": [], "destination": []}
ddosBlacklist = {"source": [], "destination": []}
ddosWatchlist = {}
ddosBlocklist = []
ddosInterval = 3
ddosMaxPacket = 15
ddosFirstPacket = {}
ruleNumber = 2
ruleMax = 9999
async def icmpHandler(log):
    global ddosWhitelist, ddosBlocklist, ddosWatchlist
    global ddosFirstPacket
    try:
        timeMatch = re.match(r"(\d+):(\d+):(\d+)\.(\d+)", log)
        addressMatch = re.search(r"(\S+)\s>\s([^:]+): ([^,]+),", log)
        hour = timeMatch.group(1)
        minute = timeMatch.group(2)
        second = timeMatch.group(3)
        millisecond = timeMatch.group(4)
        source = addressMatch.group(1)
        destination = addressMatch.group(2)
        icmpType = addressMatch.group(3)
        currentTime = Time(hour, minute, second, millisecond)
    except Exception as e:
        print(log)
        print(e)

    if icmpType.find("echo reply") != -1:
        return

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

    sourceTracked = source in ddosFirstPacket
    sourceDiffTime = currentTime.diffTime(ddosFirstPacket[source]["time"]) if sourceTracked else 0
    sourceTotalTrack = ddosFirstPacket[source]["count"] if sourceTracked else 0
    if not sourceTracked or sourceDiffTime >= ddosInterval:
        ddosFirstPacket[source] = {
                "time" : currentTime,
                "count" : 1,
                }
    else:
        ddosFirstPacket[source]["count"] += 1

    sourceBlocked = source in ddosBlocklist
    if sourceDiffTime < ddosInterval and sourceTotalTrack > ddosMaxPacket and not sourceBlocked:
        sourceWatched = source in ddosWatchlist
        if not sourceWatched:
            Print("Block by port")
            ddosBlocklist += [source]
            ddosWatchlist[source] = "port"
            asyncio.create_task(blockByPort(source, ddosBlocklist, ddosWatchlist))
        elif ddosWatchlist[source] == "port":
            Print("Block by mac")
            ddosBlocklist += [source]
            ddosWatchlist[source] = "mac"
            asyncio.create_task(blockByMac(source, ddosBlocklist, ddosWatchlist))
        elif ddosWatchlist[source] == "mac":
            Print("Block by ip")
            ddosBlocklist += [source]
            ddosWatchlist[source] = "ip"
            asyncio.create_task(blockByIp(source, ddosBlocklist, ddosWatchlist))
        elif ddosWatchlist[source] == "ip":
            Print("Blacklist")
            ddosWatchlist.pop(source, None)
            ddosBlacklist["source"] += [source]
            asyncio.create_task(blockBlacklist(source))

    sourceWatched = source in ddosWatchlist
    if not sourceWatched:
        print(f"{str(sourceDiffTime):7.7}, {str(sourceTotalTrack):5.5} | {str(currentTime):15.15} | {source} > {destination} : {icmpType}")
    else:
        pass
        Print(f"{str(sourceDiffTime):7.7}, {str(sourceTotalTrack):5.5} | {str(currentTime):15.15} | {source} > {destination} : {icmpType}")

async def packetHandler(log):
    if log.find("proto ICMP") != -1:
        await icmpHandler(bufferLine)

bufferLine = ""
async def parse(line):
    global bufferLine
    newData = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newData, line):
        if bufferLine:
            await packetHandler(bufferLine)
        await asyncio.sleep(0)

        bufferLine = line
    else:
        bufferLine += line

async def tail(filename):
    global bufferLine
    f = open(filename)

    while True:
        line = f.readline()
        if not line:
            await asyncio.sleep(0)
            continue
        await parse(line)

async def initRouter():
    interfaces = await getInterfaces()
    configureList = []
    configureList += [f"delete firewall name blocked"]
    for i in interfaces:
        configureList += [f"delete interfaces {i} firewall"]
    await quickConfigure(configureList)

async def main():
    #await initRouter()
    await tail("./tcpdump.log")

def test():
    #await quickConfigure([
    #    f"set firewall name block rule {myRuleNumber} action reject"
    #    f"set firewall name block rule {myRuleNumber} source mac-address {mac}"
    #    ])
    vyos = pexpect.spawn(f"ssh vyos@192.168.100.1")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline("configure")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline("configure")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline(f"set firewall name block rule 2 action reject")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline(f"set firewall name block rule 2 source mac-address 08:00:27:75:18:cb")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline("commit")
    vyos.expect("vyos@vyos")
    print(vyos)
    vyos.sendline("save")
    vyos.expect("vyos@vyos")
    print(vyos)

if __name__ == "__main__":
    asyncio.run(main())
    #test()

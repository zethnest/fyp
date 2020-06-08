#!/usr/bin/python

import pexpect
import asyncio
import re
from timeclass import Time

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

def stopSession(vyos):
    print("Stopping Session")
    vyos.sendline("exit")
    print("Session Stopped")

async def getArp():
    vyos = await startSession()
    vyos.sendline("show protocols static arp")
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

async def blockByPort(port):
    await block(f"set interfaces ethernet {port} disable")
    await unblockByPort(port)

ddosWhitelist = {
        "source": {
            },
        "destination": {
            },
        }
ddosBlacklist = {
        }
ddosWaitlist = {
        "byPort": {},
        "byMAC": {},
        "byIP": {},
        }
lastTime = {}
firstPacket = {}
packetInLimit = {}
packetLimit = 15
async def icmpHandler(log):
    global lastTime
    global firstPacket
    global ddosWaitlist, ddosBlacklist, ddosWhitelist
    timeMatch = re.match(r"(\d+):(\d+):(\d+)\.(\d+)", log)
    addressMatch = re.search(r"(\S+)\s>\s([^:]+):", log)
    hour = timeMatch.group(1)
    minute = timeMatch.group(2)
    second = timeMatch.group(3)
    millisecond = timeMatch.group(4)
    source = addressMatch.group(1)
    destination = addressMatch.group(2)

    currentTime = Time(hour, minute, second, millisecond)

    diffSecond = 0
    if source in lastTime:
        diffSecond = currentTime.diffTime(lastTime[source])
        diffFirstPacket = firstPacket[source].diffTime(currentTime) if source in firstPacket else 0
        if source in firstPacket:
            if diffSecond > 3 or diffFirstPacket > 3:
                firstPacket[source] = currentTime
            else:
                packetInLimit[source] = packetInLimit[source]+1 if source in packetInLimit else 1
        else:
            firstPacket[source] = currentTime

    if source in packetInLimit:
        if packetInLimit[source] >= packetLimit and not source in ddosWaitlist["byPort"]:
            ddosWaitlist["byPort"][source] = True
            asyncio.create_task(blockByPort(source))

    if source in ddosWhitelist["source"] or destination in ddosWhitelist["destination"]:
        Print(f"Skipped {source} & {destination}")
        print(f"{log}")
        return
    if source in ddosBlacklist or destination in ddosBlacklist:
        #TODO implement blocking
        Print("block port")
        return

    print(ddosWaitlist)
    print(f"{diffSecond:.5f}s | {source} > {destination}")
    lastTime[source] = currentTime

bufferLine = ""
async def parse(line):
    global bufferLine
    newData = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newData, line):
        bufferLine = bufferLine.strip()

        #if bufferLine:
        #    if bufferLine.find("proto ICMP") != -1:
        #        await icmpHandler(bufferLine)
        await asyncio.sleep(0.1)
        if bufferLine.find("35080") != -1:
            asyncio.create_task(blockByPort("eth7"))

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

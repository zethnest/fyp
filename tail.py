#!/usr/bin/python
import math
import re
import time
import asyncio
from vyos import Vyos

vyos = Vyos("vyos", "192.168.100.1")

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

class Time:
    def __init__(self, strHour, strMinute, strSecond, strMillisecond):
        self.__hour = int(strHour)
        self.__minute = int(strMinute)
        self.__second = int(strSecond)
        self.__millisecond = float(f"0.{strMillisecond}")

    def diffTime(self, otherTime):
        return abs(self.toSeconds() - otherTime.toSeconds())

    def toSeconds(self):
        return self.__hour*3600 + self.__minute*60 + self.__second + self.__millisecond

    def fromSeconds(seconds):
        return Time(math.floor(seconds/3600%60),
                math.floor(seconds/60%60),
                math.floor(seconds%60),
                float(seconds-int(seconds)))

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
bufferLog = ''

async def unblocker(ip, time):
    global ddosWaitlist, vyos
    Print(f"waiting {time} to unblock")
    await asyncio.sleep(time)
    Print("unblocking")
    vyos.quickConfigure(f"delete interfaces ethernet eth0 disable")
    Print("unblocked")
    ddosWaitlist["byPort"].pop(ip, None)

def blocker(ip):
    global ddosWaitlist, vyos
    Print("blocking")
    vyos.quickConfigure(f"set interfaces ethernet eth0 disable")
    Print("blocked")
    ddosWaitlist["byPort"][ip] = True
    print(ddosWaitlist["byPort"])
    asyncio.create_task(unblocker(ip, 10))

def icmpHandler(log):
    global lastTime
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
            Print("LIMIT REACHED")
            blocker(source)

    if source in ddosWhitelist["source"] or destination in ddosWhitelist["destination"]:
        Print(f"Skipped {source} & {destination}")
        print(f"{log}")
        return
    if source in ddosBlacklist or destination in ddosBlacklist:
        #TODO implement blocking
        Print("block port")
        return

    if not source in ddosWaitlist["byPort"]:
        print(f"{diffSecond:.5f}s | {source} > {destination}")
    lastTime[source] = currentTime

async def parse(line):
    global bufferLog, printCount

    newLog = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newLog, line):
        bufferLog = bufferLog.strip()

        if re.search("proto ICMP", bufferLog):
            icmpHandler(bufferLog)

        bufferLog = line
    else:
        bufferLog += line

    await asyncio.sleep(0.01)

async def tail(filename):
    with open(filename) as f:
        while True:
            line = ''
            while len(line) == 0 or line[-1] != "\n":
                log = f.readline()
                if log == '':
                    continue
                line += log
            await parse(line)

asyncio.run(tail("./tcpdump.log"))

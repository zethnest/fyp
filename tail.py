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

oldPrint = print
def print(arg):
    oldPrint(f"{altColor()}{arg}{color.end}")

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
    oldPrint(f"waiting {time} to unblock")
    await asyncio.asleep(time)
    oldPrint("unblocking")
    vyos.quickConfigure(f"delete interfaces ethernet eth0 disable")
    oldPrint("unblocked")
    ddosWaitlist["byPort"][ip] = False

async def blockUnblock(ip):
    global ddosWaitlist, vyos
    oldPrint("blocking")
    vyos.quickConfigure(f"set interfaces ethernet eth0 disable")
    oldPrint("blocked")
    ddosWaitlist["byPort"][ip] = True
    asyncio.create_task(unblocker(ip, 10))
    #block by IP
    #vyos.quickConfigure(f"set firewall group address-group BLOCKED-IP address {ip}")
    #await asyncio.sleep(10)
    #vyos.quickConfigure(f"delete firewall group address-group BLOCKED-IP address {ip}")

def blockHandler(ip):
    if ip in ddosWaitlist["byIP"]:
        #block by ip
        pass
    elif ip in ddosWaitlist["byMAC"]:
        #block by mac
        pass
    elif ip in ddosWaitlist["byPort"]:
        #block by ip
        pass
    else:
        pass

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

        if source in firstPacket:
            if diffSecond > 3 or (source in firstPacket and firstPacket[source].diffTime(currentTime) > 3):
                firstPacket[source] = currentTime
            else:
                packetInLimit[source] = packetInLimit[source]+1 if source in packetInLimit else 1
        else:
            firstPacket[source] = currentTime

    if source in packetInLimit:
        if packetInLimit[source] >= packetLimit and not source in ddosWaitlist["byPort"]:
            asyncio.create_task(blockUnblock(source))

    if source in ddosWhitelist["source"] or destination in ddosWhitelist["destination"]:
        oldPrint(f"Skipped {source} & {destination}")
        print(f"{log}")
        return
    if source in ddosBlacklist or destination in ddosBlacklist:
        #TODO implement blocking
        oldPrint("block port")
        return

    print(f"{diffSecond:.5f}s | {source} > {destination}")
    lastTime[source] = currentTime

def parse(line):
    global bufferLog, printCount

    newLog = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newLog, line):
        bufferLog = bufferLog.strip()

        if re.search("proto ICMP", bufferLog):
            icmpHandler(bufferLog)

        bufferLog = line
    else:
        bufferLog += line

async def tail(filename):
    with open(filename) as f:
        while True:
            line = ''
            while len(line) == 0 or line[-1] != "\n":
                log = f.readline()
                if log == '':
                    await asyncio.sleep(0)
                    continue
                line += log

            parse(line)

def main():
    asyncio.run(tail("./tcpdump.log"))

if __name__ == "__main__":
    main()

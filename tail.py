#!/usr/bin/python
import math
import time
import re

import vyosinteract

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
        return Time(math.floor(seconds/3600%60), math.floor(seconds/60%60), math.floor(seconds%60), float(seconds-int(seconds)))

def altColor(num):
    return altColors[num%len(altColors)]

bufferLog = ''
printCount = 0

oldPrint = print
def print(arg):
    global printCount
    printCount += 1
    oldPrint(arg)

ddosWhitelist = {
        "source": {
            },
        "destination": {
            },
        }
ddosBlacklist = {
        }
ddosWatchlist = {
        "byPort": {},
        "byMAC": {},
        "byIP": {},
        }
lastTime = {}
firstPacket = {}
packetInLimit = {}
packetLimit = 15

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
            if diffSecond > 3:
                firstPacket[source] = currentTime
            else:
                if source in packetInLimit:
                    packetInLimit[source] += 1
        else:
            firstPacket[source] = currentTime

    if source in ddosWhitelist["source"] or destination in ddosWhitelist["destination"]:
        oldPrint(f"Skipped {source} & {destination}")
        print(f"{altColor(printCount)}{log}{color.end}")
        return
    if source in ddosBlacklist or destination in ddosBlacklist:
        #TODO implement blocking
        oldPrint("block port")
        return

    print(f"{altColor(printCount)}"+
          f"{diffSecond:.5f}s | {source} > {destination}"+
          f"{color.end}")
    #print(f"{altColor(printCount)}{log}{color.end}")

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

with open("./tcpdump.log") as f:
    while True:
        line = ''
        while len(line) == 0 or line[-1] != "\n":
            log = f.readline()
            if log == '':
                time.sleep(0.1)
                continue
            line += log

        parse(line)

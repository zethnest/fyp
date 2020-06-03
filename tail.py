#!/usr/bin/python
import time
import re

class color:
    header = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'
colors = [color.green , color.blue , color.yellow]

bufferLog = ''
printCount = 0

oldPrint = print
def print(arg):
    global printCount
    printCount += 1
    oldPrint(arg)

ddosWhitelist = {
        "nurizz.local": True,
        "_gateway"    : True,
        }
ddosBlacklist = {
        }
ddosWatchlist = {
        "byPort": {},
        "byMAC": {},
        "byIP": {},
        }
def icmpHandler(log):
    timeMatch = re.match(r"(\d+):(\d+):(\d+\.\d+)", log)
    addressMatch = re.search(r"(\S+)\s>\s([^:]+):", log)
    hour = timeMatch.group(1)
    minute = timeMatch.group(2)
    second = timeMatch.group(3)
    source = addressMatch.group(1)
    destination = addressMatch.group(2)
    if source in ddosWhitelist or destination in ddosWhitelist:
        return
    if source in ddosBlacklist or destination in ddosBlacklist:
        #TODO implement blocking
        oldPrint("block port")
    print(f"{colors[printCount%len(colors)]}{hour}:{minute}:{second} | {source} > {destination}{color.end}")

def parse(line):
    global bufferLog, printCount

    newLog = r"\d+:\d+:\d+\.\d+"
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

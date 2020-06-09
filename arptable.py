import re

class ArpTable:
    arpTable = []

    def __init__(self, table):
        self.__raw = table
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

    def __str__(self):
        return self.__raw

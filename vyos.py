#!/usr/bin/python
import pexpect
import re

class Vyos:
    configMode = False
    child = None
    user = "vyos"
    ip = "192.168.100.1"
    destination = f"{user}@{ip}"

    def __init__(self, user, ip):
        self.configMode = False
        self.connection = None
        self.destination = f"{user}@{ip}"

    def startSession(self):
        self.connection = pexpect.spawn(f"ssh {self.destination}")
        self.connection.expect('vyos@vyos:~\$ ')

    def stopSession(self):
        if self.configMode:
            self.exitConfig()
        self.connection.sendline('exit')
        self.connection = None

    def send(self, command):
        self.connection.sendline(command)
        self.connection.expect('vyos@vyos')

    def getBefore(self):
        before = self.connection.before.decode('utf-8')
        line1 = before.find("\r\n\r") + 3
        return before[line1:].strip()

    def enterConfig(self):
        self.send('configure')
        self.configMode = True

    def saveConfig(self, saveMode = ""):
        if self.configMode:
            self.send(f'save {saveMode}')
            before = self.getBefore()
            if before.find('Warning:') != -1:
                print(before)

    def commitConfig(self):
        if self.configMode:
            self.send('commit')
            before = self.getBefore()
            if before.find('Commit Failed') != -1:
                print(before)

    def exitConfig(self, forced = False):
        if self.configMode:
            if forced:
                self.send('exit discard')
                self.configMode = False
            else:
                self.send('exit')
                before = self.getBefore()
                if before.find('Cannot exit') != -1:
                    print(before)
                else:
                    self.configMode = False

    def quickConfigure(self, command):
        hasConnection = self.connection
        if not hasConnection:
            self.startSession()
        inConfig = self.configMode
        if not inConfig:
            self.enterConfig()
        self.configure(command)
        self.commitConfig()
        self.saveConfig()
        if not inConfig:
            self.exitConfig(True)
        if not hasConnection:
            self.stopSession()

    def configure(self, command):
        if self.configMode:
            self.send(command)
        else:
            self.quickConfigure(command)

    def getConfig(self, command):
        if self.configMode:
            self.send(f"show {command}")
            return self.getBefore()
        else:
            self.enterConfig()
            before = self.getConfig()
            self.exitConfig()
            return before

    def getStatus(self, command):
        if not self.configMode:
            self.send(f"show {command}")
            return self.getBefore()
        else:
            self.exitConfig()
            before = self.getStatus()
            self.enterConfig()
            return before

    def getArp(self):
        return self.getStatus("protocols static arp")

class ArpTable:
    arpTable = []

    def __init__(self, table):
        headerMatch = re.search(r"(Address\s+)(HWtype\s+)(HWaddress\s+)(Flags\s+)(Mask\s+)(.*)", table)

        line1 = table.find("\r\n") + 2
        table = table[line1:]
        for line in table.splitlines():
            if line == '':
                break
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

#vyos = Vyos("vyos","192.168.100.1")
#vyos.quickConfigure('set interfaces ethernet eth0 disable')
#vyos.startSession()
#vyos.configure('set interfaces ethernet eth0 disable')
#arpTable = ArpTable(vyos.getArp())
#print(arpTable.getMacFromIp("192.168.100.5"))
#vyos.stopSession()
#child.interact()

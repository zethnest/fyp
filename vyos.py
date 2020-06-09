#!/usr/bin/python
import pexpect
import re
from arptable import ArpTable

class Vyos:
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
        before = re.sub(r'\x1b\[.', '', self.connection.before.decode('utf-8'))
        print(before.encode())
        line1 = before.find("\r\n\r") + 3
        return before[line1:]

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

    def getFirewallRules(self):
        return self.getConfig("firewall name")

if __name__ == "__main__":
    vyos = Vyos("vyos","192.168.100.1")
    vyos.startSession()
    print(vyos.getArp())
    arpTable = ArpTable(vyos.getArp())
    #vyos.enterConfig()
    #print(vyos.getFirewallRules())
    #vyos.quickConfigure('set interfaces ethernet eth0 disable')
    #vyos.configure('set interfaces ethernet eth0 disable')
    #child.interact()
    vyos.stopSession()

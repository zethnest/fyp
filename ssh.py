#!/usr/bin/python
import pexpect

configMode = False
child = None

def startSession():
    global child, configMode
    child = pexpect.spawn("ssh vyos@192.168.56.107")
    child.expect('vyos@vyos:~\$ ')
    configMode = False

def exitSession():
    global child, configMode
    child.sendline('exit')

def enterConfigMode():
    global child, configMode
    child.sendline('configure')
    child.expect('vyos@vyos# ')
    configMode = True

def saveConfig():
    global child, configMode
    if configMode:
        child.sendline('save')
        child.expect('vyos@vyos# ')
    else:
        print("Not in config mode")
        return

def commitConfig():
    global child, configMode
    if configMode:
        child.sendline('commit')
        child.expect('vyos@vyos# ')
    else:
        print("Not in config mode")
        return

def exitConfigMode():
    global child, configMode
    if configMode:
        child.sendline('exit')
        child.expect('vyos@vyos:~\$ ')
        configMode = False
    else:
        return

def configure(command):
    global child, configMode
    if configMode:
        child.sendline(command)
        child.expect('vyos@vyos# ')
    else:
        enterConfigMode()
        configure(command)
        commitConfig()
        saveConfig()
        exitConfigMode()
        return

startSession()
configure('set interfaces ethernet eth5 disable')
exitSession()
child.interact()

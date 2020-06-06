#!/usr/bin/python

import pexpect
import asyncio
import re

async def unblock():
    print("waiting 10s to unblock")
    await asyncio.sleep(10)
    print("unblocking")
    vyos = pexpect.spawn(f"ssh vyos@192.168.100.1")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("configure")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("delete interfaces ethernet eth0 disable")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("commit")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("save")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("exit discard")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("exit")
    print("unblocked")

async def block():
    print("blocking")
    vyos = pexpect.spawn(f"ssh vyos@192.168.100.1")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("configure")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("set interfaces ethernet eth0 disable")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("commit")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("save")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("exit discard")
    await asyncio.sleep(0.1)
    vyos.expect("vyos@vyos")
    vyos.sendline("exit")
    print("blocked")
    asyncio.create_task(unblock())

async def count():
    for i in range(100):
        print(i)
        await asyncio.sleep(1)

bufferLine = ""
async def parse(line):
    global bufferLine
    newData = r"(\d+:\d+:\d+\.\d+|\s+IP)"
    if re.match(newData, line):
        bufferLine = bufferLine.strip()

        print(bufferLine)
        await asyncio.sleep(0.5)
        if bufferLine.find("35080") != -1:
            asyncio.create_task(block())

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

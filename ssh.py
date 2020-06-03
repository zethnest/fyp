import pexpect

child = pexpect.spawn("ssh localhost uname -a")
child.expect(["[pP]assword: "])
child.sendline('test123')
child.expect(pexpect.EOF)

print(child.before)
child.interact()

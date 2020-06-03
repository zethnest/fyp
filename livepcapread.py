import time

with open("/tmp/capfile", 'rb') as f:
    while True:
        log = f.readline()
        if log == b'':
            continue
        print(log)

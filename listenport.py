import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener = ('localhost',10000)

sock.bind(listener)

sock.listen(1)

while True:
    print('waiting for connection', file=sys.stderr)
    connection, client_address = sock.accept()
    try:
        print(f'connection from {client_address}', file=sys.stderr)
        while True:
            data = connection.recv(16)
            print('received %s' % data, file=sys.stderr)
            if data:
                print('sending data back to the client', file=sys.stderr)
                connection.sendall(data)
            else:
                print(f'no more data from {client_address}', file=sys.stderr)
                break
    finally:
        connection.close()




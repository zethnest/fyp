import dpkt
import datetime
import socket
import os
from dpkt.compat import compat_ord

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

filename = "/tmp/capfile"
while os.stat(filename).st_size == 0:
    continue
pcap = dpkt.pcap.Reader(open(filename, 'rb'))

for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        print(f"Non IP Packet type not supported {eth.data.__class__.__name__}\n")
        continue

    ip = eth.data

    if isinstance(ip.data, dpkt.icmp.ICMP):
        icmp = ip.data

        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        print(f"Timestamp: {str(datetime.datetime.utcfromtimestamp(timestamp))}")
        print(f"Ethernet Frame: {mac_addr(eth.src)} -> {mac_addr(eth.dst)} , {eth.type}")
        print(f"IP: {inet_to_str(ip.src)}, {inet_to_str(ip.dst)}, len={ip.len}, ttl={ip.ttl}, DF={do_not_fragment}, MF={more_fragments}, offset={fragment_offset}")
        print(f"ICMP: type:{icmp.type} code:{icmp.code} checksum:{icmp.sum} data: {repr(icmp.data)}\n")

# sniff(iface="enp0s25", count=10, prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"))

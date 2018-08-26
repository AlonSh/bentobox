import socket
import fcntl
import struct

from scapy.all import *
from scapy.layers.inet import IP, ICMP

CLIENT_IP = None
SRC_TCP_PORT = 50000
SERVER_IP = None


def get_ip_address(interface_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack(b'256s', interface_name[:15])
    )[20:24])


def packet_callback(p: Packet):
    global CLIENT_IP, SERVER_IP
    if 'ICMP' in p and p['ICMP'].chksum == 1337:
        print("Forwarding TCP message!")
        inner_ip_packet = IP(p['ICMP'].payload.load)
        if 'TCP' not in inner_ip_packet:
            return
        
        CLIENT_IP = inner_ip_packet.src
        inner_ip_packet.src = SERVER_IP
        inner_ip_packet['TCP'].sport = 50000
        del inner_ip_packet.chksum
        del inner_ip_packet['TCP'].chksum
        send(inner_ip_packet)

    if 'TCP' in p and p['TCP'].dport == 50000:
        print('Sending back the answer')
        icmp_packet = IP(dst=CLIENT_IP) / ICMP(chksum=1337, type=39) / p
        send(icmp_packet)


def start_proxy_server():
    global SERVER_IP
    SERVER_IP = get_ip_address(b'eth0')

    sniff(filter='icmp or tcp', iface='eth0', prn=packet_callback, count=0)


if __name__ == '__main__':
    start_proxy_server()

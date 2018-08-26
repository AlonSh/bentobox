import socket
import fcntl
import struct

from scapy.all import *
from scapy.layers.inet import IP, ICMP


CLIENT_INNER_IP_TO_INTERNET_IP = {}


def packet_callback(p: Packet):
    if 'ICMP' in p and p['ICMP'].chksum == 1337 and p.sniffed_on == 'eth0':
        print("Forwarding TCP message!")
        inner_ip_packet = IP(p['ICMP'].payload.load)
        if 'TCP' not in inner_ip_packet:
            return

        CLIENT_INNER_IP_TO_INTERNET_IP[inner_ip_packet.src] = p['IP'].src

        del inner_ip_packet.chksum
        del inner_ip_packet['TCP'].chksum
        send(inner_ip_packet, iface='tun0')

    if 'TCP' in p and p.sniffed_on == 'tun0':
        print('Sending back the answer')
        icmp_packet = IP(dst=CLIENT_INNER_IP_TO_INTERNET_IP[p['IP'].dst]) / ICMP(chksum=1337, type=0) / p
        ls(icmp_packet)
        send(icmp_packet)


def start_proxy_server():
    sniff(filter='icmp or tcp', iface=['eth0', 'tun0'], prn=packet_callback, count=0)


if __name__ == '__main__':
    start_proxy_server()

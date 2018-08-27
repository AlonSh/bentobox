import socket
import fcntl
import struct
import pytun

from scapy.all import *
from scapy.layers.inet import IP, ICMP, Ether

CLIENT_INNER_IP_TO_INTERNET_IP = {}
GATEWAY_MAC = '06:03:61:31:25:aa'

tunnel_socket = pytun.TunTapDevice("tun0")
# tunnel_socket.addr = '10.0.1.1'
# tunnel_socket.dstaddr = '0.0.0.0'
# tunnel_socket.netmask = '255.255.255.0'
# tunnel_socket.mtu = 1472


def packet_callback(p: Packet):
    if 'ICMP' in p and p.sniffed_on == 'eth0':
        print("Forwarding TCP message!")
        print(p['ICMP'].payload)
        print(p['ICMP'].payload.load)
        inner_ip_packet = IP(p['ICMP'].payload.load)
        print(bytes(inner_ip_packet))
        print(inner_ip_packet['IP'].dst)

        # ls(inner_ip_packet)
        if 'TCP' not in inner_ip_packet:
            print('inner is not TCP')
            return

        CLIENT_INNER_IP_TO_INTERNET_IP[inner_ip_packet.src] = p['IP'].src

        # wrapped_ether = Ether() / inner_ip_packet
        tunnel_socket.write(bytes(inner_ip_packet)[:4] + bytes(inner_ip_packet))

        # ls(wrapped_ether)
        # sendp(wrapped_ether, iface='tun0')

    if 'TCP' in p and p.sniffed_on == 'tun0':
        packet_destination = p['IP'].dst
        if packet_destination not in CLIENT_INNER_IP_TO_INTERNET_IP:
            print('Ignoring outgoing packet')
            return
        print('Sending back the answer')
        wrapped_icmp_destination = CLIENT_INNER_IP_TO_INTERNET_IP[packet_destination]
        icmp_packet = IP(dst=wrapped_icmp_destination) / ICMP(chksum=1337, type=0) / p
        ls(icmp_packet)
        send(icmp_packet)


def start_proxy_server():
    sniff(filter='icmp or tcp', iface=['eth0', 'tun0'], prn=packet_callback, count=0)


if __name__ == '__main__':
    start_proxy_server()

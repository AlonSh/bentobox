from scapy.all import *
from scapy.layers.inet import IP


def packet_callback(p: Packet):
    tcp_packet = IP(p['ICMP'].payload.load)
    send(tcp_packet)


def start_proxy_server():
    sniff(filter='icmp and src host 192.168.88.254', iface='en0', prn=packet_callback, count=10)


if __name__ == '__main__':
    start_proxy_server()

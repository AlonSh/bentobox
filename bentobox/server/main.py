from scapy.all import *
from scapy.layers.inet import IP

CLIENT_IP = None
SRC_TCP_PORT = 50000


def packet_callback(p: Packet):
    global CLIENT_IP
    if 'ICMP' in p and p['ICMP'].chksum == 1337:
        print("Forwarding TCP message!")
        inner_ip_packet = IP(p['ICMP'].payload.load)
        CLIENT_IP = inner_ip_packet.src
        inner_ip_packet.src = '192.168.88.237'
        inner_ip_packet['TCP'].sport = 50000
        del inner_ip_packet.chksum
        del inner_ip_packet['TCP'].chksum
        send(inner_ip_packet)

    if 'TCP' in p and p['TCP'].dport == 50000:
        print("received TCP packet")
        ls(p)


def start_proxy_server():
    sniff(filter='icmp or tcp', iface='en0', prn=packet_callback, count=0)


if __name__ == '__main__':
    start_proxy_server()

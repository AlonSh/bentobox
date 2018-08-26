
FROM centos:7

# Assigining an IP address and mask to 'tun0' interface
RUN ifconfig tun0 mtu 1472 up 10.0.1.1 netmask 255.255.255.0

# Preventing the kernel to reply to any ICMP pings
RUN echo 1 | dd of=/proc/sys/net/ipv4/icmp_echo_ignore_all

# Enabling IP forwarding
RUN echo 1 | dd of=/proc/sys/net/ipv4/ip_forward

# Adding an iptables rule to masquerade for 10.0.0.0/8
RUN iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE


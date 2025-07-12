from scapy.all import IP, ICMP, Ether, sendp

# Change these values:
fake_ip = "1.2.3.4"                      # spoofed IP
target_ip = ""              # your Kali IP
target_mac = "aa:bb:cc:dd:ee:ff"         # dummy MAC for test
interface = "wlan1"                      # your sniffing interface

# Craft packet
pkt = Ether(src=target_mac)/IP(src=fake_ip, dst=target_ip, ttl=20)/ICMP()

# Send multiple packets
sendp(pkt, iface=interface, count=50, inter=0.05)

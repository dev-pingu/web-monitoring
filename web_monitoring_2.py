import pyshark
import time


# define interface
# 192.168.137.226
networkInterface = "Local Area Connection* 2"

ip = []
n = int(input("Enter number of clients in network: "))
for i in range(n):
    ip_addr = input(f"IP of client {i + 1}: ")
    ip.append(ip_addr)

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)

packets1 = []
packets2 = []

print("listening on %s" % networkInterface)

for packet in capture.sniff_continuously(packet_count=1000):
    # adjusted output
    try:
        # get timestamp
        localtime = time.asctime(time.localtime(time.time()))

        print(".", end="")
        # output packet info
        if packet.ip.src == ip[0] or packet.ip.dst == ip[0]:
            packets1.append([localtime, packet])

        if(packet.ip.src == ip[1]):
            packets2.append([localtime, packet])

    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        pass
with open("client1.txt", "w") as f:
    for packs in packets1:
        protocol = packs[1].transport_layer  # protocol type
        src_addr = packs[1].ip.src  # source address
        src_port = packs[1][protocol].srcport  # source port
        dst_addr = packs[1].ip.dst  # destination address
        dst_port = packs[1][protocol].dstport  # destination port
        f.write(
            "%s Source IP: %s:%s <-> Dest IP%s:%s (%s)\n"
            % (packs[0], src_addr, src_port, dst_addr, dst_port, protocol)
        )
with open("client2.txt", "w") as f:
    for packs in packets2:
        protocol = packs[1].transport_layer  # protocol type
        src_addr = packs[1].ip.src  # source address
        src_port = packs[1][protocol].srcport  # source port
        dst_addr = packs[1].ip.dst  # destination address
        dst_port = packs[1][protocol].dstport  # destination port
        f.write(
            "%s Source IP: %s:%s <-> Dest IP%s:%s (%s)\n"
            % (packs[0], src_addr, src_port, dst_addr, dst_port, protocol)
        )

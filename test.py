import time
import subprocess
import random
from layers import Ether, IP, ICMP, UDP, TCP, DNS
from functions import send, sr, sendp, sniff


if __name__ == "__main__":
    my_ip = "172.16.161.129"
    my_mac = "00:0c:29:a4:0d:6d" 
    dst_mac = "00:50:56:ed:09:1a" #gatway MAC from arp command

    # Example 1: ICMP Echo
    # print("Ping example")
    # eth = Ether(src_mac=my_mac, dst_mac=dst_mac)
    # ip = IP(src_ip=my_ip, dst_ip="8.8.8.8")
    # icmp = ICMP(id=1, seq=1, type=8)

    # #pkt = Ether(src_mac=my_mac, dst_mac=dst_mac)/IP(src_ip=my_ip, dst_ip="8.8.8.8")/ICMP(id=1, seq=1, data=b'')
    # pkt = eth / ip / icmp
    # #TODO: Doesnt work yet
    # send(pkt) #show send works at Layer 3 (watch in wireshark for send and reply)
    
    # #show sendp works at Layer 2 (watch in wireshark)
    # icmp.seq = 2 #update sequence number so google responds to this ping
    # sendp(pkt, "ens160")

    # #show sr works at Layer 3
    # time.sleep(1) #make sure we don't send before seq 2 reply comes back
    # icmp.seq = 3
    # ret_pkt = sr(pkt)
    # print(pkt)
    # print(ret_pkt)
    # ret_pkt.show()
    # print("\n\n")

    #Example 2: DNS Resolution

    print("\nDNS example")
    domain_name = "vibrantcloud.org"
    pkt = Ether(src_mac=my_mac, dst_mac=dst_mac)/IP(src_ip=my_ip, dst_ip="8.8.8.8", proto=17)/UDP(sport=12345, dport=53)/DNS(qname=domain_name)
    dns = sr(pkt)
    # dns.show()
    # dns_layer = dns.get_layer("DNS")  #helper method to get a specified layer
    # print(dns_layer.addr)
    # addr = dns_layer.addr
    print("\n\n")
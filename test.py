import time
import subprocess
import random
from layers import Ether, IP, ICMP #UDP, TCP, DNS, 
from functions import send, sr, sendp, sniff


if __name__ == "__main__":
    my_ip = "172.25.165.174"
    my_mac = "00:0c:29:a8:d0:96" 
    dst_mac = "00:50:56:f5:9e:21" #gatway MAC from arp command

    
    # Example 1: ICMP Echo
    print("Ping example")
    eth = Ether(src_mac=my_mac, dst_mac=dst_mac)
    ip = IP(src_ip=my_ip, dst_ip="8.8.8.8")
    icmp = ICMP(id=1, seq=1, type=8)

    #pkt = Ether(src_mac=my_mac, dst_mac=dst_mac)/IP(src_ip=my_ip, dst_ip="8.8.8.8")/ICMP(id=1, seq=1, data=b'')
    pkt = eth / ip / icmp
    print((IP(src_ip=my_ip, dst_ip="8.8.8.8")/ICMP(id=1, seq=1, type=8)).build().hex())
    send(pkt) #show send works at Layer 3 (watch in wireshark for send and reply)
    
    # #show sendp works at Layer 2 (watch in wireshark)
    icmp.seq = 2 #update sequence number so google responds to this ping
    sendp(pkt, "en0")


    # #show sr works at Layer 3
    # time.sleep(1) #make sure we don't send before seq 2 reply comes back
    # icmp.seq = 3
    # ret_pkt = sr(pkt)
    # ret_pkt.show()
    # print("\n\n")
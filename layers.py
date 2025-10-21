
import struct
from itertools import accumulate
import socket

class Packet:
    def __init__(self):
        self.payload = None

    def add_payload(self, payload):
        if payload is None:
            return
        if isinstance(self.payload, Packet):
            self.payload.add_payload(payload)
        else:
            self.payload = payload

    def __truediv__(self, other):
        self.add_payload(other)
        return self
    
    def show(self):
        print("########",self.__class__.__name__, "#######" )
        dict = vars(self)
        underlayer = None
        for key in dict:
            if key != 'payload':
                print(key, ":", dict[key])
            else:
                underlayer = dict[key]
        if underlayer:
            underlayer.show()

class Ether(Packet):
    def __init__(self, dst_mac=None, src_mac=None, bytes=None):
        super().__init__()
        if not bytes:
            self.dst_mac=dst_mac
            self.src_mac=src_mac
            self.type=2048
            self.payload = None
        else:
            self.dst_mac, self.src_mac, self.type,  =\
                  struct.unpack("!6s6sH", bytes) #self.payload
            self.src_mac = self.bytes2mac(self.src_mac)
            self.dst_mac = self.bytes2mac(self.dst_mac)

    def mac2bytes(self, mac):
        return bytes.fromhex(mac.replace(":",""))
    
    def bytes2mac(self, bytes):
        return ":".join(f"{b:02x}" for b in bytes) #written with help from GenAI
    
    def build(self):
        if self.payload:
            return struct.pack("!6s6sH", self.mac2bytes(self.dst_mac), self.mac2bytes(self.src_mac), self.type) + self.payload.build
        else:
            return struct.pack("!6s6sH", self.mac2bytes(self.dst_mac), self.mac2bytes(self.src_mac), self.type)

class IP(Packet):
    def __init__(self, src_ip, dst_ip, bytes=None):
        super().__init__()
        self.version = 69 #B - one nibble to header length shifted with first nibble representing ipv4
        #self.ihl     = 'None'
        self.tos     = 0 #B 
        self.len     = 20 #H
        self.id      = 1 #H
        self.flags   = 0 #B
        self.frag    = 0 #B
        self.ttl     = 64 #H
        self.proto   = 0 #B
        self.chksum  = 0 #H
        self.src_ip     = socket.inet_aton(src_ip) #4s
        self.dst_ip     = dst_ip #4s
        #self.options = '[]'
    
    #Method to return the bytes for the layer to be used to transmit a packet.
    def build(self):
        return struct.pack("!BBHHBBHBH4s4s", self.version, self.tos, self.len, self.id, self.flags, self.frag, self.ttl, self.proto, self.chksum, self.src_ip, socket.inet_aton(self.dst_ip)) + self.payload.build()


class ICMP(Packet):
    def __init__(self, id, seq, type, bytes=None):
        self.type       = type
        self.code       = '0'
        self.chksum     = 'None'
        self.id         = id
        self.seq        = seq
        self.ts_ori     = '21297305'
        self.ts_rx      = '21297305'
        self.ts_tx      = '21297305'
        self.gw         = "'0.0.0.0'"
        self.ptr        = '0'
        self.reserved   = '0'
        self.length     = '0'
        self.addr_mask  = "'0.0.0.0'"
        self.nexthopmtu = '0'
        self.unused     = "b''"
        self.extpad     = "b''"
        self.ext        = 'None'

    def build(self):
        return b'0'

# class UDP(Packet):
#     def __init__(self, sport, dport, payload)

bytes = Ether("00:00:00:06:08:76", "8e:68:46:88:2c:5a").build()
print(bytes.hex())
newether = Ether(bytes=bytes).show()
print(Ether(bytes=bytes))
#print(IP(src_ip="192.168.159.129", dst_ip="8.8.8.8").build())



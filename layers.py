
import struct
from itertools import accumulate
import socket

class Packet:
    def __init__(self):
        self.payload = None

    def get_layer(self, layer):
        if self.__class__.__name__ == layer:
            return self
        else:
            if self.payload:
                return self.payload.get_layer(layer)
            else:
                return None

    def add_payload(self, payload):
        if payload is None:
            return
        if isinstance(self.payload, Packet):
            print(self)
            print(payload)
            self.payload.add_payload(payload)
        else:
            if isinstance(self, IP) and isinstance(payload, UDP) or isinstance(payload, TCP):
                payload.src_ip = self.src_ip
                payload.dst_ip = self.dst_ip
                if isinstance(payload, UDP):
                    print("an UDP div")
                    self.proto = 0x11
                    print(self.proto)
            self.payload = payload

    def __truediv__(self, other):
        self.add_payload(other)
        return self
    
    def show(self):
        print("########",self.__class__.__name__, "#######" )
        dict = vars(self)
        underlayer = None
        for key in dict:
            if key != "bytes":
                if key != 'payload':
                    print(key, ":", dict[key])
                else:
                    underlayer = dict[key]
        if 'bytes' in dict and dict['bytes']: print("bytes:", dict["bytes"].hex())
        if underlayer:
            if isinstance(underlayer, Packet):
                underlayer.show()
            else:
                print(underlayer.hex())

def calculate_checksum(data): #GenAI helped with understanding bitshifting, masking, typing, and folding convention
    if len(data) % 2 == 1:
        data = data + b'\x00'
    sum = 0x0000
    for i in range(0, len(data), 2):
        sum = sum + ((data[i] << 8) + data[i+1])
        sum = (sum & 0xFFFF) + (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16)
    return sum ^ 0xFFFF #(~sum).to_bytes(2, 'big') 

class Ether(Packet):
    def __init__(self, dst_mac=None, src_mac=None, bytes=None):
        super().__init__()
        if not bytes:
            self.dst_mac=dst_mac
            self.src_mac=src_mac
            self.type=2048
            self.payload = None
            self.bytes = struct.pack("!6s6sH", self.mac2bytes(self.dst_mac), self.mac2bytes(self.src_mac), self.type)
        else:
            self.dst_mac, self.src_mac, self.type = struct.unpack("!6s6sH", bytes[:14]) #self.payload
            if self.type == 0x800:
                print("Identified an IP Header!")
                self.payload = IP(bytes=bytes[14:])
            self.src_mac = self.bytes2mac(self.src_mac)
            self.dst_mac = self.bytes2mac(self.dst_mac)
            self.bytes = bytes

    def mac2bytes(self, mac):
        return bytes.fromhex(mac.replace(":",""))
    
    def bytes2mac(self, bytes):
        return ":".join(f"{b:02x}" for b in bytes) #written with help from GenAI
    
    def build(self):
        if self.payload:
            return  self.bytes + self.payload.build()
        else:
            return self.bytes

class IP(Packet):
    def __init__(self, src_ip=None, dst_ip=None, proto=1, bytes=None):
        super().__init__()
        if not bytes:
            self.version_ihl = 69 #B - combined to represent IPv4 and header length 5.
            self.tos     = 0 #B 
            self.len     = 0 #H
            self.id      = 4 #H
            self.flags_frag = 0x4000 #H - number for dont fragment
            self.ttl     = 128 #64 #B
            self.proto   = proto #B
            self.chksum  = 0 #H
            self.src_ip = src_ip #4s
            self.dst_ip = dst_ip #4s
            self.bytes=struct.pack("!BBHHHBBH4s4s", self.version_ihl, self.tos, self.len, self.id, self.flags_frag, self.ttl, self.proto, self.chksum, socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip)) #flag-frag combined
        else:
            self.version_ihl, self.tos, self.len, self.id, self.flags_frag, self.ttl, self.proto, self.chksum, self.src_ip, self.dst_ip = struct.unpack("!BBHHHBBH4s4s", bytes[:20])
            if self.proto == 0x0001:
                print("Identified ICMP Payload!")
                self.payload = ICMP(bytes=bytes[20:])
            if self.proto == 0x11:
                self.payload = UDP(bytes=bytes[20:])
            self.src_ip = socket.inet_ntoa(self.src_ip)
            self.dst_ip = socket.inet_ntoa(self.dst_ip)
            self.bytes = bytes

    #Method to return the bytes for the layer to be used to transmit a packet.
    def build(self):
        if self.payload:
            payload_bytes = self.payload.build()
            print("building ip", self.proto)
            return struct.pack("!BBHHHBBH4s4s", self.version_ihl, self.tos, self.len, self.id, self.flags_frag, self.ttl, self.proto, self.chksum, socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip)) + payload_bytes
        else:
            return self.bytes
    
    def add_payload(self, payload):
        self.chksum = calculate_checksum(self.bytes + payload.build())
        self.len = 5 + len(payload.build())
        return super().add_payload(payload)


class ICMP(Packet):
    def __init__(self, id=None, seq=None, type=None, bytes=None):
        super().__init__()
        if not bytes:
            self.type       = type #B
            self.code       = 0 #B
            self.chksum     = 0 #H
            self.id         = id #H
            self.seq        = seq #H
            self.ping = b'\x00' * 4
            self.chksum = calculate_checksum(struct.pack("!BBHHH32s", self.type, self.code, 0, self.id, self.seq, self.ping))
            self.bytes =  struct.pack("!BBHHH32s", self.type, self.code, self.chksum, self.id, self.seq, self.ping)
            self.payload = None
        else:
            self.type, self.code, self.chksum, self.id, self.seq, self.payload = struct.unpack("!BBHHH32s", bytes)

    def build(self):
        return self.bytes

class UDP(Packet):
    def __init__(self, sport=None, dport=None, bytes=None):
        if not bytes:
            self.sport  = 53
            self.dport  = 53
            self.src_ip = None
            self.dst_ip = None
            self.len    = 0
            self.chksum = 0
            self.payload = None
        else:
            self.sport, self.dport, self.len, self.chksum = struct.unpack("!HHHH", bytes[:8])
            #for this lab we assume payload is always DNS
            self.payload = DNS(bytes=bytes[8:])

    def add_payload(self, payload):
        assert self.src_ip and self.dst_ip, "IP Layer not created yet!"
        self.len = 8 + len(payload.build())
        pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton(self.src_ip), socket.inet_aton(self.dst_ip), 0x00, 4, self.len)
        header = struct.pack("!HHHH", self.sport, self.dport, self.len, 0)
        self.chksum = calculate_checksum(pseudo_header + header + payload.build())
        return super().add_payload(payload)
    
    def build(self):
        if self.payload:
            return struct.pack("!HHHH", self.sport, self.dport, self.len, self.chksum) + self.payload.build()
        else:
            return struct.pack("!HHHH", self.sport, self.dport, self.len, self.chksum)


class DNS(Packet):
    def __init__(self, qname=None, bytes=None):
        if not bytes:
            self.id      = 0x3121 #random number chosen for demonstration #H
            # self.qr      = ('0')
            # self.opcode  = ('0')
            # self.aa      = ('0')
            # self.tc      = ('0')
            # self.rd      = ('1')
            # self.ra      = ('0')
            # self.z       = ('0')
            # self.ad      = ('0')
            # self.cd      = ('0')
            # self.rcode   = ('0')
            self.flags = 0x0100 #H
            self.qdcount = 1 #H
            self.ancount = 0 #H
            self.nscount = 0 #H
            self.arcount = 0 #H
            self.qname     = qname
            self.qtype = 1 #H
            self.qclass = 1 #H
            self.addr = None
        else:
            self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack("!HHHHHH", bytes[:12])
            self.qname = self.bytes2qname(bytes[12:])
            self.addr = socket.inet_ntoa(*struct.unpack("!4s", bytes[-4:]))

    def bytes2qname(self, bytes): #GenAI assisted during debugging
        print(bytes)
        i = 0
        ret = bytearray()
        while bytes[i] != 0:           
            ret += bytes[i+1:i+bytes[i]+1] + b'.'
            i += 1 + bytes[i]
        return ret[:-1].decode()


    def qname2bytes(self, qname):
        parts = qname.split(".")
        ret = bytearray()
        for part in parts:
            ret.append(len(part))
            ret += part.encode()
        ret.append(0)         #GenAI advised on bytearray
        return ret
    
    def build(self):
        return struct.pack("!HHHHHH", self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount)\
        + self.qname2bytes(self.qname) + b'\x00\x01' + b'\x00\x01' #query for Type A and IN
    
class TCP(Packet):
    def __init__(self, seq, ack):
        self.sport    = 20
        self.dport    = 80
        self.seq      = seq
        self.ack      = ack
        self.dataofs  = None
        self.reserved = ('0')
        self.flags    = ('<Flag 2 (S)>')
        self.window   = ('8192')
        self.chksum   = ('None')
        self.urgptr   = ('0')
        self.options  = ("b''")
    
# bytes = Ether("00:00:00:06:08:76", "8e:68:46:88:2c:5a").build()
# print(bytes.hex())
# newether = Ether(bytes=bytes).show()
# print(Ether(bytes=bytes))
# ip = IP(src_ip="192.168.159.129", dst_ip="8.8.8.8").build()
# newip = IP(ip)
# newip.show()
#print(IP(src_ip="192.168.159.129", dst_ip="8.8.8.8").build())



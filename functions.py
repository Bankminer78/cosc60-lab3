import socket
import struct
import time

def send(pkt):
    """
    Transmit packet bytes at layer 3 (IP layer).
    Handles both Ether/IP packets and IP-only packets.
    """
    # Navigate to IP layer if packet starts with Ether
    if hasattr(pkt, '__class__') and pkt.__class__.__name__ == 'Ether':
        ip_pkt = pkt.payload
    else:
        ip_pkt = pkt
    
    # Create raw socket for layer 3 transmission
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    # Get destination IP from packet
    dst_ip = ip_pkt.dst_ip
    
    # Build packet bytes starting from IP layer
    pkt_bytes = ip_pkt.build()
    
    # Send the packet
    sock.sendto(pkt_bytes, (dst_ip, 0))
    sock.close()
    
    print(f"[*] Sent packet to {dst_ip}")


def sendp(pkt, interface):
    """
    Transmit packet bytes at layer 2 (Ether layer).
    Requires packet to start with Ether layer.
    """
    # Create raw socket for layer 2 transmission
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    
    # Bind to the specified interface
    sock.bind((interface, 0))
    
    # Build complete packet bytes starting from Ether layer
    if hasattr(pkt, '__class__') and pkt.__class__.__name__ == 'Ether':
        pkt_bytes = pkt.build()
    else:
        raise ValueError("sendp requires packet starting with Ether layer")
    
    # Send the packet
    sock.send(pkt_bytes)
    sock.close()
    
    print(f"[*] Sent packet on interface {interface}")


def sr(pkt, timeout=5, ether_class=None):
    """
    Send packet at layer 3 and receive reply at layer 2.
    Returns the received packet object built from the reply bytes.
    
    Args:
        pkt: The packet to send
        timeout: Socket timeout in seconds (default 5)
        ether_class: Pass Ether class here to rebuild packets from bytes
    """

    # Navigate to IP layer if packet starts with Ether
    if hasattr(pkt, '__class__') and pkt.__class__.__name__ == 'Ether':
        ip_pkt = pkt.payload
    else:
        ip_pkt = pkt
    
    # Create raw socket for sending at layer 3
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    # Create raw socket for receiving at layer 2
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(timeout)
    
    # Get destination IP
    dst_ip = ip_pkt.dst_ip
    
    # Build and send packet bytes
    pkt_bytes = ip_pkt.build()
    send_sock.sendto(pkt_bytes, (dst_ip, 0))
    send_sock.close()
    
    print(f"[*] Sent packet to {dst_ip}, waiting for reply...")
    
    try:
        # Receive reply at layer 2
        reply_bytes, addr = recv_sock.recvfrom(65535)
        recv_sock.close()
        
        # Build packet object from received bytes
        if ether_class is None:
            print("[!] Warning: Ether class not provided, returning raw bytes")
            return reply_bytes
        
        reply_pkt = ether_class(bytes_data=reply_bytes)
        
        print("[*] Received reply")
        return reply_pkt
        
    except socket.timeout:
        recv_sock.close()
        print("[!] Timeout: No reply received")
        return None


def sniff(interface=None, timeout=5, ether_class=None):
    """
    Receive one packet at layer 2 and build packet object from bytes.
    Returns the packet object.
    
    Args:
        interface: Network interface to listen on (optional)
        timeout: Socket timeout in seconds (default 5)
        ether_class: Pass Ether class here to rebuild packets from bytes
    """

    # Create raw socket for receiving at layer 2
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    
    # Bind to interface if specified
    if interface:
        sock.bind((interface, 0))
    
    sock.settimeout(timeout)
    
    try:
        # Receive one packet at layer 2
        pkt_bytes, addr = sock.recvfrom(65535)
        sock.close()
        
        # Build packet object from received bytes
        if ether_class is None:
            print("[!] Warning: Ether class not provided, returning raw bytes")
            return pkt_bytes
        
        pkt = ether_class(bytes_data=pkt_bytes)
        
        print("[*] Captured packet")
        return pkt
        
    except socket.timeout:
        sock.close()
        print("[!] Timeout: No packet received")
        return None
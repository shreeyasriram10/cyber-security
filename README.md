# cyber-security
import socket
import struct
import datetime
from collections import defaultdict

# Dictionary to track packet statistics
packet_stats = defaultdict(int)

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC Address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Log anomalies to a file
def log_anomaly(ip, count):
    with open("anomalies.log", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} - Anomaly detected: {ip} sent {count} packets\n")

# Packet Sniffer Function
def sniff():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("[+] Network Sniffer Initialized...")
    
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            if eth_proto == 8:
                ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
                packet_stats[src_ip] += 1  # Track packets per source IP
                
                print(f"[+] {datetime.datetime.now()} - {src_ip} -> {target_ip} [TTL: {ttl}, Protocol: {proto}]")
                
                # Detect unusual packet bursts
                if packet_stats[src_ip] > 100:
                    print(f"[!!] Potential Anomaly Detected from {src_ip} - {packet_stats[src_ip]} packets")
                    log_anomaly(src_ip, packet_stats[src_ip])
    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer...")
        conn.close()

if __name__ == "__main__":
    sniff()

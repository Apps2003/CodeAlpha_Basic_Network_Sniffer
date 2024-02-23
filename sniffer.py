import socket
import struct

def main():
    # Create a raw socket and bind it to the network interface
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(("192.168.0.106", 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Sniff packets
    sniff(conn)

def sniff(conn):
    while True:
        # Receive packet
        raw_data, _ = conn.recvfrom(65536)

        # Extract Ethernet header (first 14 bytes)
        eth_header = raw_data[:14]

        # Unpack Ethernet header
        dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', eth_header)

        # Print MAC addresses and Ethernet protocol
        print(f"Source MAC: {get_mac_address(src_mac)} Destination MAC: {get_mac_address(dest_mac)} EtherType: {eth_proto}")

def get_mac_address(mac):
    return ":".join("{:02x}".format(b) for b in mac)

if __name__ == '__main__':
    main()

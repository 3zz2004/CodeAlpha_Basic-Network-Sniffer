import socket
import struct

def network_sniffer():
    # Create a raw socket to capture all packets
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print("Sniffer is running... Press Ctrl+C to stop.")

    try:
        while True:
            # Receive a packet
            raw_data, addr = sniffer_socket.recvfrom(65535)

            # Parse Ethernet frame
            eth_header = raw_data[:14]
            eth_data = struct.unpack("!6s6sH", eth_header)
            dest_mac = format_mac(eth_data[0])
            src_mac = format_mac(eth_data[1])
            proto = socket.htons(eth_data[2])

            print(f"\nEthernet Frame:")
            print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {proto}")

            # Display payload data
            payload_data = raw_data[14:]
            print(f"Payload: {payload_data[:60]}...")

    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    finally:
        sniffer_socket.close()


def format_mac(mac_bytes):
    """Convert MAC address from bytes to a readable string."""
    return ':'.join(map("{:02x}".format, mac_bytes))


# Run the sniffer
if name == "main":
    network_sniffer()
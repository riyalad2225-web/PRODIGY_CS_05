from scapy.all import sniff

def analyze_packet(packet):
    print("\n--- Packet Captured ---")

    # IP Layer
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    # Protocol
    if packet.haslayer("TCP"):
        print("Protocol: TCP")
    elif packet.haslayer("UDP"):
        print("Protocol: UDP")
    else:
        print("Protocol: Other")

    # Payload (limited view)
    if packet.haslayer("Raw"):
        data = packet["Raw"].load
        print(f"Payload: {data[:50]}")  # first 50 bytes only

def main():
    print("Starting packet capture... Press CTRL+C to stop.")
    
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()
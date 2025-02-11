from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {source_ip} -> Destination IP: {dest_ip} | Protocol: {protocol}")
        if packet.haslayer(Raw):
            print(f"Payload Data: {packet[Raw].load}")
        print("-" * 50)
def start_sniffing(interface="eth0"):
    print(f"Sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()

from scapy.all import *

# Define target domain and source IP
target_domain = "google.com"
source_ip = "1.2.3.4"

# Build DNS query packet
dns_req = DNS(rd=1, qd=DNS(R$qname=target_domain, qtype="A"))
udp_req = UDP(dport=53)
ip_req = IP(src=source_ip, dst="8.8.8.8")

# Try sending the packet and catching any errors
try:
    send(ip_req / udp_req / dns_req)
    print("Packet sent successfully!")
except Exception as e:
    # Extract the error code from the exception
    error_code = e.args[0].args[0]
    print(f"Error sending packet: {error_code}")

# Optionally, capture and display the response
print(sniff(filter=f"udp port 53 and dst 8.8.8.8", count=1))

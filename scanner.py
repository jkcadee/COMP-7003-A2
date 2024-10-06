from scapy.all import sniff
import sys

def human_readable_addresses(hex_str):
    readable_str = ""
    for i in range(0, 8, 2):
        dec = int(hex_str[i:i+2], 16)
        readable_str += str(dec)
        if i != 6:
            readable_str += ":"
    
    return readable_str

def human_readable_bytes(hex_str):
    dec = int(hex_str, 16)
    return str(dec)

def binary_flags(hex_str):
    bin_str = ""
    for i in hex_str:
        int_i = int(i)
        bin_str += f"{int_i:04b} "
    
    return bin_str.strip()

def parse_arp(hex_data):
    hw_address_type = hex_data[28:32]
    protocol_type = hex_data[32:36]
    hw_length = hex_data[36:38]
    protocol_length = hex_data[38:40]
    operation = hex_data[40:44]
    sender_hw_address = hex_data[44:56]
    sender_pro_address = hex_data[56:64]
    target_hw_address = hex_data[64:76]
    target_pro_address = hex_data[76:84]

    send_protocol_address_readable = human_readable_addresses(sender_pro_address)
    tar_protocol_address_readable = human_readable_addresses(target_pro_address)

    print("--------------- PACKET TYPE: ARP ---------------")
    print(f"Hardware Address Type: {hw_address_type} / {human_readable_bytes(hw_address_type)}")
    print(f"Protocol Type: {protocol_type} / {human_readable_bytes(protocol_type)}")
    print(f"Hardware Length: {hw_length} / {human_readable_bytes(hw_length)}")
    print(f"Protocol Length: {protocol_length} / {human_readable_bytes(protocol_length)}")
    print(f"Operation: {operation} / {human_readable_bytes(operation)}")
    print(f"Sender Hardware Address: {':'.join(sender_hw_address[i:i+2] for i in range(0, 12, 2))}")
    print(f"Sender Protocol Address: {':'.join(sender_pro_address[i:i+2] for i in range(0, 8, 2))} / {send_protocol_address_readable}")
    print(f"Target Hardware Address: {':'.join(target_hw_address[i:i+2] for i in range(0, 12, 2))}")
    print(f"Target Protocol Address: {':'.join(target_pro_address[i:i+2] for i in range(0, 8, 2))} / {tar_protocol_address_readable}")

def parse_udp(hex_data):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    length = hex_data[76:80]
    checksum = hex_data[80:84]

    print("--------------- PACKET TYPE: UDP ---------------")
    print(f"Source Port: {source_port} / {human_readable_bytes(source_port)}")
    print(f"Destination Port: {destination_port} / {human_readable_bytes(destination_port)}")
    print(f"Length: {length} / {human_readable_bytes(length)}")
    print(f"Checksum: {checksum} / {human_readable_bytes(checksum)}")

def parse_tcp(hex_data):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    sequence_num = hex_data[76:84]
    ack_num = hex_data[84:92]
    header_length = hex_data[92:93]
    reserved = hex_data[93:94]
    flags = hex_data[94:96]
    window_size = hex_data[96:100]
    checksum = hex_data[100:104]
    urgent_pointer = hex_data[104:108]

    print("--------------- PACKET TYPE: TCP ---------------")
    print(f"Source Port: {source_port} / {human_readable_bytes(source_port)}")
    print(f"Destination Port: {destination_port} / {human_readable_bytes(destination_port)}")
    print(f"Sequence Number: {sequence_num} / {human_readable_bytes(sequence_num)}")
    print(f"Acknowlegement Number: {ack_num} / {human_readable_bytes(ack_num)}")
    print(f"Header Length: {header_length} / {human_readable_bytes(header_length)}")
    print(f"Reserved: {reserved} / {human_readable_bytes(reserved)}")
    print(f"Flags: {flags} / {human_readable_bytes(flags)} / {binary_flags(flags)}")
    print(f"Window Size: {window_size} / {human_readable_bytes(window_size)}")
    print(f"Checksum: {checksum} / {human_readable_bytes(checksum)}")
    print(f"Urgent Pointer: {urgent_pointer} / {human_readable_bytes(urgent_pointer)}")

def parse_ipv4(hex_data):
    version = hex_data[28:29]
    header_length = hex_data[29:30]
    type_of_service = hex_data[30:32]
    total_length = hex_data[32:36]
    identification = hex_data[36:40]
    flags = hex_data[40:43]
    fragment_offset = hex_data[43:44]
    time_to_live = hex_data[44:46]
    protocol = hex_data[46:48]
    checksum = hex_data[48:52]
    source_add = hex_data[52:60]
    destination_add = hex_data[60:68]

    source_address_readable = human_readable_addresses(source_add)
    destination_address_readable = human_readable_addresses(destination_add)
    
    print("--------------- PACKET TYPE: IPV4 ---------------")

    print(f"Version: {version} / {human_readable_bytes(version)}")
    print(f"Header Length: {header_length} / {human_readable_bytes(header_length)}")
    print(f"Type of Service: {type_of_service} / {human_readable_bytes(type_of_service)}")
    print(f"Total Length: {total_length} / {human_readable_bytes(total_length)}")
    print(f"Identification: {identification} / {human_readable_bytes(identification)}")
    print(f"Flags + Offset: {flags} + {fragment_offset} / {human_readable_bytes(flags + fragment_offset)} / {binary_flags(flags + fragment_offset)}")
    print(f"Time to Live: {time_to_live} / {human_readable_bytes(time_to_live)}")
    print(f"Protocol: {protocol} / {human_readable_bytes(protocol)}")
    print(f"Checksum: {checksum} / {human_readable_bytes(checksum)}")
    print(f"Source Address: {':'.join(source_add[i:i+2] for i in range(0, 8, 2))} / {source_address_readable}")
    print(f"Destination Address: {':'.join(destination_add[i:i+2] for i in range(0, 8, 2))} / {destination_address_readable}")

    if protocol == "06":
        parse_tcp(hex_data)
    elif protocol == "11": # this is technically 16 + 1, 17 being udp protocol
        parse_udp(hex_data)
    
def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

    if ether_type == "0800":
        parse_ipv4(hex_data)
    elif ether_type == "0806":
        parse_arp(hex_data)

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

def capture_input():
    # order of input: [protocol filter] and [host filter]
    accepted_protocols = ["tcp", "udp", "arp"]
    captured_filter = sys.argv[1]
    captured_filter = captured_filter.lower().strip()
    if any(protocol in captured_filter for protocol in accepted_protocols):
        capture_packets("eth0", captured_filter, 1)
    else:
        print("Incorrect input, please specify the type of protocol (tcp, udp, arp) you are trying to filter for.")

capture_input()


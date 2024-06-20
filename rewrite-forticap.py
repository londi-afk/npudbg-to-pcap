#!/usr/bin/python3

"""
This script can convert dumps from Fortigate CLI. The command to capture debugs should be following:

diagnose sniffer packet npudbg '' 6 0 l

The output should look like:

2024-05-15 15:42:11.125364 npudbg -- 192.168.1.1.443 -> 192.168.2.1.5246: fin 1795716699 ack 3600550434
0x0000   38c0 ea7d 7e32 8890 09fd dc74 0800 4500        8..}~2.....t..E.
0x0010   0034 d2d4 4000 7b06 a89c c0a8 0101 c0a8        .4..@.{.....6...
0x0020   0201 01bb 147e 6b08 765b d69c 0a22 8011        .....~k.v[..."..
0x0030   2000 a95e 0000 0101 080a 67e3 bbfa 2249        ...c......g..."I
0x0040   0a88

You can add filters to the packet debug.

"""

import struct
import binascii
from datetime import datetime
import sys

def print_help():
    print("Usage: python3 rewrite-forticap.py <input_file> <output_file>")
    print("<input_file>: Path to the input file containing the npudbg with timestamps.")
    print("<output_file>: Path to the output .pcap file.")

def parse_hex_dump(file_path):
    print(f'Parsing HEX DUMP from {file_path}')
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    packets = []
    current_packet = []
    current_timestamp = None
    for line in lines:
        if line.startswith('0x'):
            current_packet.append(line[7:55].replace(' ', '').rstrip())
        else:
            if current_packet:
                packets.append((current_timestamp, ''.join(current_packet)))
                current_packet = []
            # Handle the timestamp line
            timestamp_line = line.strip()
            if timestamp_line:
                # Parse the timestamp from the line (example: 2024-05-15 15:42:11.063310)
                timestamp_str = timestamp_line.split()[0] + ' ' + timestamp_line.split()[1]
                current_timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
    
    if current_packet:
        packets.append((current_timestamp, ''.join(current_packet)))
    
    return packets

def create_pcap(packets, output_file):
    # pcap file header (global header for pcap file format)
    pcap_header = struct.pack(
        'IHHIIII',
        0xa1b2c3d4,   # Magic number
        2,            # Major version number
        4,            # Minor version number
        0,            # GMT to local correction
        0,            # Accuracy of timestamps
        65535,        # Max length of captured packets, in octets
        1             # Data link type (Ethernet)
    )

    with open(output_file, 'wb') as f:
        f.write(pcap_header)
        for timestamp, packet in packets:
            if ' ' in packet:
                continue
            binary_data = binascii.unhexlify(packet)
            ts_sec = int(timestamp.timestamp())
            ts_usec = timestamp.microsecond
            pcap_packet_header = struct.pack(
                'IIII',
                ts_sec,              # Timestamp seconds
                ts_usec,             # Timestamp microseconds
                len(binary_data),    # Number of octets of packet saved in file
                len(binary_data)     # Actual length of packet
            )
            f.write(pcap_packet_header)
            f.write(binary_data)

    print(f"PCAP file {output_file} created successfully.")

def main():
    if len(sys.argv) != 3:
        print_help()
        sys.exit(1)

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    print(f'Will create PCAP file from {input_file_path} to {output_file_path}')

    # Parse hex dump from the input file
    packets = parse_hex_dump(input_file_path)

    # Create pcap file from parsed packets
    create_pcap(packets, output_file_path)

if __name__ == "__main__":
    main()

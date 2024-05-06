import os
import time
from scapy.all import *
from colorama import Fore
from pyfiglet import Figlet
from termcolor import colored

separator = "." * 60
separator_hash = "#" * 80
pcap_folder = "logs"
pcap_base_filename = "Packets_logs"
pcap_extension = ".pcap"
timestamp = time.strftime("%Y%m%d%H%M%S")
pcap_filename = pcap_base_filename + "_" + timestamp + pcap_extension
pcap_filepath = os.path.join(pcap_folder, pcap_filename)

if not os.path.exists(pcap_folder):
    os.makedirs(pcap_folder)

pcap_writer = PcapWriter(pcap_filepath, append=True, sync=True)

def show_results_noport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size):
    print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
    print("")
    print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
    print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
    print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
    print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
    print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
    print("")
    print(colored(separator_hash, "cyan"))
    print("")

def show_results_withport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size, src_port, dst_port):
    print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
    print("")
    print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
    print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
    print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
    print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
    print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
    print(f"{colored('Source Port:       ', 'blue')}{colored(src_port, 'yellow')}")
    print(f"{colored('Destination Port:  ', 'blue')}{colored(dst_port, 'yellow')}")
    print("")
    print(colored(separator_hash, "cyan"))
    print("")

def show_results_arp(packet_name, src_ip, src_mac, dst_ip, dst_mac, size):
    print(f"{colored(packet_name, 'green')} {colored('Packet ...', 'green')}")
    print("")
    print(f"{colored('Source IP:         ', 'blue')}{colored(src_ip, 'yellow')}")
    print(f"{colored('Source MAC:        ', 'blue')}{colored(src_mac, 'yellow')}")
    print(f"{colored('Destination IP:    ', 'blue')}{colored(dst_ip, 'yellow')}")
    print(f"{colored('Destination MAC:   ', 'blue')}{colored(dst_mac, 'yellow')}")
    print(f"{colored('Packet Size:       ', 'blue')}{colored(size, 'yellow')}")
    print("")
    print(colored(separator_hash, "cyan"))
    print("")

def analyzer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet.src
        dst_mac = packet.dst

        if packet.haslayer(ICMP):
            packet_name = "ICMP"
            size = len(packet[ICMP])
            show_results_noport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size)

        if packet.haslayer(TCP):
            packet_name = "TCP"
            src_port = packet.sport
            dst_port = packet.dport
            size = len(packet[TCP])
            show_results_withport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size, src_port, dst_port)

        if packet.haslayer(UDP):
            packet_name = "UDP"
            src_port = packet.s
import os
import time
from scapy.all import *

pcap_folder = "logs"
pcap_base_filename = "Packets_logs"
pcap_extension = ".pcap"
timestamp = time.strftime("%Y%m%d%H%M%S")
pcap_filename = pcap_base_filename + "_" + timestamp + pcap_extension
pcap_filepath = os.path.join(pcap_folder, pcap_filename)

if not os.path.exists(pcap_folder):
    os.makedirs(pcap_folder)

pcap_writer = PcapWriter(pcap_filepath, append=True, sync=True)

def show_results_noport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size):
    print(f"Packet Name: {packet_name}")
    print(f"Source IP: {src_ip}")
    print(f"Source MAC: {src_mac}")
    print(f"Destination IP: {dst_ip}")
    print(f"Destination MAC: {dst_mac}")
    print(f"Packet Size: {size}")
    print("")

def show_results_withport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size, src_port, dst_port):
    print(f"Packet Name: {packet_name}")
    print(f"Source IP: {src_ip}")
    print(f"Source MAC: {src_mac}")
    print(f"Destination IP: {dst_ip}")
    print(f"Destination MAC: {dst_mac}")
    print(f"Packet Size: {size}")
    print(f"Source Port: {src_port}")
    print(f"Destination Port: {dst_port}")
    print("")

def show_results_arp(packet_name, src_ip, src_mac, dst_ip, dst_mac, size):
    print(f"Packet Name: {packet_name}")
    print(f"Source IP: {src_ip}")
    print(f"Source MAC: {src_mac}")
    print(f"Destination IP: {dst_ip}")
    print(f"Destination MAC: {dst_mac}")
    print(f"Packet Size: {size}")
    print("")

def analyzer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet.src
        dst_mac = packet.dst

        if packet.haslayer(ICMP):
            packet_name = "ICMP"
            size = len(packet[ICMP])
            show_results_noport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size)

        if packet.haslayer(TCP):
            packet_name = "TCP"
            src_port = packet.sport
            dst_port = packet.dport
            size = len(packet[TCP])
            show_results_withport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size, src_port, dst_port)

        if packet.haslayer(UDP):
            packet_name = "UDP"
            src_port = packet.sport
            dst_port = packet.dport
            size = len(packet[UDP])
            show_results_withport(packet_name, src_ip, src_mac, dst_ip, dst_mac, size, src_port, dst_port)

    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        src_mac = packet[ARP].hwsrc
        dst_mac = packet[ARP].hwdst
        packet_name = "ARP"
        size = len(packet[ARP])
        show_results_arp(packet_name, src_ip, src_mac, dst_ip, dst_mac, size)

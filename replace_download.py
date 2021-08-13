from netfilterqueue import NetfilterQueue
import subprocess
import scapy.all as scapy

# http == port 80

queue = NetfilterQueue()


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:

            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in str(scapy_packet[scapy.Raw].load):
                    print("[+].EXE Request")
                    print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                pass
                # print("Response")
                # print(scapy_packet.show())

        except IndexError:
            pass

    packet.accept()


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

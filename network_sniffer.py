from scapy.all import sniff, IP, TCP, UDP, conf
import platform

try:
    from scapy.arch.windows import L3RawSocket
except Exception:
    L3RawSocket = None

def packet_callback(packet):
    print("\n" + "=" * 60)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        else:
            print(f"Protocol Number: {packet[IP].proto}")

        print(f"Packet Length  : {len(packet)} bytes")

# On Windows, scapy may not have a layer-2 provider (winpcap/npf).
# Use a layer-3 socket as a fallback so the script can run without WinPcap.
def run_sniffer():
    if platform.system() == "Windows" and L3RawSocket is not None:
        try:
            sock = L3RawSocket()
            sniff(prn=packet_callback, store=False, count=50, opened_socket=sock)
            return
        except Exception:
            pass

    # Default attempt
    sniff(prn=packet_callback, store=False, count=50)


try:
    run_sniffer()
except RuntimeError as e:
    msg = str(e)
    if 'winpcap' in msg.lower() or 'layer 2' in msg.lower():
        print('Error: live layer-2 packet capture is unavailable on this system.')
        print('Install Npcap/WinPcap and run with administrator privileges to enable sniffing,')
        print('or run this script on Linux/macOS where libpcap is available.')
    else:
        raise


from scapy.all import *
import socket

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)

def sniffp(pkt):
    if(pkt[IP].src == IPAddr):
        return ("Packet type = Response, " + "Packet Size = " + str(len(pkt)) + " Sequence number = " + str(pkt.seq))
    else:
        return ("Packet type = Request, " + "Packet Size = " + str(len(pkt)) + " Sequence number = " + str(pkt.seq))

if __name__ == "__main__":
    packet = sniff(prn = sniffp, filter = "icmp",count = 5)
    print(packet)
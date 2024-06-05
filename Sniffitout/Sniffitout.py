import sys
import random
import os
import transformers as tf
import numpy as np
import scapy
import pyshark
import socket
import struct
import datetime
from scapy.all import sniff, IP, IPv6, ARP
import pandas as pd
import tkinter as tk
import threading 
from threading import Thread
from tkinter import scrolledtext



core_protocols = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    17: "UDP",
    20: "HMP",
    27: "RDP",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    46: "RSVP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    88: "EIGRP",
    89: "OSPF",
    115: "L2TP",
    132: "SCTP",
    136: "UDPLite",
    137: "MPLS-in-IP"
}
link_layer_protocols = {
    2054: "ARP"  
}
core_protocols.update(link_layer_protocols)
application_protocols = {
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    53: "DNS",
    67: "DHCP",
    161: "SNMP",
    23: "Telnet",
    22: "SSH",
    5060: "SIP",
    5004: "RTP",
    5005: "RTCP"
}
core_protocols.update(application_protocols)
security_vpn_protocols = {
    443: "SSL/TLS",
    50: "IPsec",
    88: "Kerberos",
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP"
}
core_protocols.update(security_vpn_protocols)
industrial_protocols = {
    502: "Modbus",
    20000: "DNP3"
}
core_protocols.update(industrial_protocols)
cloud_virtualization_protocols = {
    4789: "VXLAN",
    47: "GRE"
}
core_protocols.update(cloud_virtualization_protocols)

def get_protocol_name(ip_proto):
    return core_protocols.get(ip_proto, "Unknown Protocol")


def packetcallback(packet):
    global ip_src
    global ip_dst
    global ip_proto
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_proto = packet[IP].proto
    elif IPv6 in packet:
        ip_src = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        ip_proto = packet[IPv6].nh
    elif ARP in packet:
        ip_src = packet[ARP].psrc
        ip_dst = packet[ARP].pdst
        ip_proto = 2054
    else:
        return
        
    ip_protocol = get_protocol_name(ip_proto)
    results_text.insert(tk.INSERT, f"Source: {ip_src}|Destionation: {ip_dst}|Protocal: {ip_protocol}|Number:{ip_proto}\n")


    
def runsniffmain():
    while True:
        sniff(prn = packetcallback)
        #df = pd.DataFrame()
        #print(df.head())
    
        #protocal_counts = df['ip_proto'].value_counts()
        #print(protocal_counts)
        
def threadedsnifftraffic():
    snifftrafficipaddrs = Thread(target=runsniffmain)
    snifftrafficipaddrs.start()

def exitprogram():
    root.quit()
    
    
root = tk.Tk()
root.title("Sniffitout")

root.geometry("850x550")  # 800x600Set initial window size

#window resizable
root.resizable(True, True)

sniffframe = tk.Frame(root, padx=10, pady=10)
sniffframe.pack(side=tk.TOP)
sniffframe.pack(side=tk.LEFT)

sniffanalyze_button = tk.Button(sniffframe, text="Sniff Traffic", command=threadedsnifftraffic)
sniffanalyze_button.pack(side=tk.TOP)

exit_button = tk.Button(sniffframe, text="Exit", command=exitprogram)
exit_button.pack(side=tk.BOTTOM)


#results
resultsframe = tk.Frame(root) #, padx=10, pady=10
resultsframe.pack(side=tk.TOP, expand=True)
#, fill=tk.BOTH, expand=True
results_text = scrolledtext.ScrolledText(resultsframe, width=95, height=40)
results_text.pack(side=tk.TOP, expand=True)
results_text.pack(side=tk.RIGHT)



root.mainloop()
from scapy.all import *

def orbit():
    print "pressed orbit"

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        if pkt[ARP].hwsrc == '74:75:48:70:ab:b4': # Orbit
            orbit()

sniff(prn=arp_monitor_callback, filter="arp", store=0)

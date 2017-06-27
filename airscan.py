#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, os, sys, signal
from scapy.all import *
from multiprocessing import Process

GRA    = '\033[90m'
RED    = '\033[91m'
GRE    = '\033[92m'
YEL    = '\033[93m'
BLU    = '\033[94m'
PUR    = '\033[95m'
CYA    = '\033[96m'
END    = '\033[00m'

interface = ''

aps   = set()
asoc  = set()
nasoc = set()

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        Dot11Layer = pkt.getlayer(Dot11)

        if Dot11Layer.addr1 == Dot11Layer.addr3 and Dot11Layer.addr1 != 'ff:ff:ff:ff:ff:ff':
            client = "%s %s" % (Dot11Layer.addr1, Dot11Layer.addr2)
            if client not in asoc:
                asoc.add(client)

                print "%s%s %s%s" % (RED, Dot11Layer.addr1, Dot11Layer.addr2, END)

        if pkt.haslayer(Dot11ProbeReq):
            Dot11ProbeReqLayer = pkt.getlayer(Dot11ProbeReq)

            if len(Dot11ProbeReqLayer.info) > 0:
                client = "%s %s" % (Dot11Layer.addr2, Dot11ProbeReqLayer.info)
                if client not in nasoc:
                    nasoc.add(client)

                    print "%s%s %s%s" % (YEL, Dot11Layer.addr2, Dot11ProbeReqLayer.info, END)

        if pkt.haslayer(Dot11Beacon):
            Dot11BeaconLayer = pkt.getlayer(Dot11Beacon)
            
            if Dot11Layer.addr2 and (Dot11Layer.addr2 not in aps):
                aps.add(Dot11Layer.addr2)

                print "%s%s %s%s" % (BLU, Dot11Layer.addr2, Dot11BeaconLayer.info, END)
    
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(0.5)
        except KeyboardInterrupt:
            break

def signal_handler(signal, frame):
    p.terminate()
    p.join()

    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='airodump scapy')
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='interface to use')

    args = parser.parse_args()

    interface = args.interface

    p = Process(target = channel_hopper)
    p.start()

    signal.signal(signal.SIGINT, signal_handler)

    sniff(iface=interface, prn=packet_handler)

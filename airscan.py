#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, time, os, sys, signal
from scapy.all import *
from multiprocessing import Process, Manager
from airjam import Airjam

GRA    = '\033[90m'
RED    = '\033[91m'
GRE    = '\033[92m'
YEL    = '\033[93m'
BLU    = '\033[94m'
PUR    = '\033[95m'
CYA    = '\033[96m'
END    = '\033[00m'

class Airscan():
    
    _instance = None

    def __init__(self):
        self.manager = Manager()
        self.aps     = self.manager.list()
        self.asoc    = self.manager.list()
        self.nasoc   = self.manager.list()
        self.flags   = self.manager.dict()

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11):
            Dot11Layer = pkt.getlayer(Dot11)
            if Dot11Layer.addr1 == Dot11Layer.addr3 and Dot11Layer.addr1 != 'ff:ff:ff:ff:ff:ff':
                client = "%s %s" % (Dot11Layer.addr1, Dot11Layer.addr2)
                if client not in self.asoc:
                    self.asoc.append(client)
                    print "%s%s %s%s" % (RED, Dot11Layer.addr1, Dot11Layer.addr2, END)

            if pkt.haslayer(Dot11ProbeReq):
                Dot11ProbeReqLayer = pkt.getlayer(Dot11ProbeReq)
                if len(Dot11ProbeReqLayer.info) > 0:
                    client = "%s %s" % (Dot11Layer.addr2, Dot11ProbeReqLayer.info)
                    if client not in self.nasoc:
                        self.nasoc.append(client)
                        print "%s%s %s%s" % (YEL, Dot11Layer.addr2, Dot11ProbeReqLayer.info, END)

            if pkt.haslayer(Dot11Beacon):
                Dot11BeaconLayer = pkt.getlayer(Dot11Beacon)
                if Dot11Layer.addr2 and (Dot11Layer.addr2 not in self.aps):
                    self.aps.append(Dot11Layer.addr2)
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                    if re.search("privacy", cap):
                        enc = 'Y'
                    else:
                        enc  = 'N'
                    
                    rssi = -(256-ord(pkt.notdecoded[-4:-3]))
                    print "%s%d %s %d %s %s%s" % (BLU, channel, enc, rssi, Dot11Layer.addr2, Dot11BeaconLayer.info, END)

    def keep_handler(self, pkt):
        return self.flags['stop_sniff']

    def channel_hop(self):
        for channel in range(1,14):
            os.system("iw dev %s set channel %d" % (self.interface, channel))
            time.sleep(0.7)
        self.flags['stop_sniff'] = True
        self.aps[:]   = []
        self.asoc[:]  = []
        self.nasoc[:] = []

    def signal_handler(self, signal, frame):
        self.flags['stop_sniff'] = True
        self.p.terminate()
        self.p.join()

    def run(self, iface):
        self.interface = iface

        self.flags['stop_sniff'] = False
        self.p = Process(target = self.channel_hop)
        self.p.start()
        signal.signal(signal.SIGINT, self.signal_handler)
        sniff(iface=self.interface, prn=self.packet_handler, stop_filter=self.keep_handler)
        self.p.terminate()
        self.p.join()

        target = raw_input("Enter target bssid fully or partially:")

        airjam = Airjam(self.interface, target)
        airjam.run()

    def getInstance():
        if Airscan._instance == None:
            Airscan._instance = Airscan()

        return Airscan._instance

    getInstance = staticmethod(getInstance)

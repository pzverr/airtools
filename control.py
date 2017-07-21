#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Pavel Zverev"
__email__  = "pzverr@gmail.com"

import os, sys
from getopt import getopt
from airscan import Airscan

def usage():
    print "\nUsage: control.py <options>\n"
    print "Options:"
    print "-i <iface>, --iface=<iface>"
    print "-h, --help"
    print ""

def parseOptions(argv):
    iface   = False

    try:
        opts, args = getopt(argv, "i:h", ["iface=", "help"])
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-i", "--iface"):
                iface = arg
        return (iface)
    except getopt.GetoptError:
        usage()
        sys.exit(2)

def main(argv):
    (iface) = parseOptions(argv)

    if iface:
        Airscan().getInstance().run(iface)
    else:
        usage()
        sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])

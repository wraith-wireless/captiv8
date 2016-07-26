#!/usr/bin/env python

""" capitv8-ui.py: Captive Portal Evasion Tool

Copyright (C) 2016  Dale V. Patterson (wraith.wireless@yandex.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

Redistribution and use in source and binary forms, with or without
modifications, are permitted provided that the following conditions are met:
 o Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 o Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 o Neither the name of the orginal author Dale V. Patterson nor the names of
    any contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

Provides the command line interface to captiv8
"""

#__name__ = 'capitv8-ui'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import argparse as ap                  # cli arg parsing
import sys                             # cli exiting
import captiv8

def execute(dev):
    print "running captiv8 on device", dev 

banner1 = """
--------------------------------------------------------------------------------
             ___     _____   _____  _______  _______  _     _   _____
           _(___)_  (_____) (_____)(__ _ __)(_______)(_)   (_) (_____)
          (_)   (_)(_)___(_)(_)__(_)  (_)      (_)   (_)   (_)(_)___(_)
          (_)    _ (_______)(_____)   (_)      (_)   (_)   (_) (_____)
          (_)___(_)(_)   (_)(_)       (_)    __(_)__  (_)_(_) (_)___(_)
            (___)  (_)   (_)(_)       (_)   (_______)  (___)   (_____)

--------------------------------------------------------------------------------
                      captiv8 v{0} Copyright {1}
""".format(captiv8.version, captiv8.__date__)
if __name__ == '__main__':
    # create arg parser and parse command line args
    #print "captiv8 v{0}".format(captiv8.version)
    print banner1
    argp = ap.ArgumentParser(description="Captive Portal Evasion")
    argp.add_argument('-i', '--interface', help="Wireless Device")
    argp.add_argument('-s', '--ssid', help="Desired SSID")
    args = argp.parse_args()
    usage = "usage: python captiv8-ui.py -i <dev> -s <ssid>"
    try:
        dname = args.interface
        ssid = args.ssid
        if dname is None or ssid is None:
            print(usage)
            sys.exit(0)
        execute(dname)
    except Exception as e:
        print e
        sys.exit(0)

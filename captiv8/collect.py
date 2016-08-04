#!/usr/bin/env python

""" collect.py: Collect/Inspect packets

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

Provides the Collector class

"""

__name__ = 'collect'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import multiprocessing as mp
import Queue
import pyric
import pyric.pyw as pyw

class Collector(mp.Process):
    """ Collects data on wireless nets """
    def __init__(self,ssid,dev,conn):
        """
         initialize Collector
         :param ssid: Name of ssid to collect on
         :param dev: device to use for collection
         :param conn: pipe connection
        """
        mp.Process.__init__(self)
        self._ssid = ssid
        self._dev = dev
        self._conn = conn

    def run(self):
        """ execution loop """
        # set up the radio for collection
        oinfo = None # the original device info
        ocard = None # the orginal card
        #ninfo = None # the new device info
        ncard = None # the new card
        try:
            # store the old card and create a new one, deleting any assoc interfaces
            oinfo = pyw.devinfo(self._dev)
            ocard = oinfo['card']
            ncard = pyw.devadd(ocard,'capt0','monitor')
            #ninfo = pyw.devinfo(ncard)
            for card,_ in pyw.ifaces(self._dev):
                if card.dev != ncard.dev:
                    pyw.devdel(card)
            if not pyw.isup(ncard): pyw.up(ncard)
        except pyric.error as e:
            self._conn.send(('error',"ERRNO {0} {1}".format(e.errno,e.strerror)))
            return

        # ececution loop
        while True:
            if self._conn.poll():
                tkn = self._conn.recv()
                if tkn == '!QUIT!': break

        # teardown the radio
        try:
            if ncard:
                ocard = pyw.devadd(ncard,self._dev,oinfo['mode'])
                pyw.devdel(ncard)
                if not pyw.isup(ocard): pyw.up(ocard)
        except pyric.error as e:
            self._conn.send(('error',"ERRNO {0} {1}".format(e.errno,e.strerror)))
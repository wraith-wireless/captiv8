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
import pyric
import pyric.pyw as pyw

# noinspection PyCallByClass
class Collector(mp.Process):
    """ Collects data on wireless nets """
    def __init__(self,conn,ssid,dev,aps,stas):
        """
         initialize Collector
         :param conn: pipe connection
         :param ssid: Name of ssid to collect on
         :param dev: device to use for collection
         :param aps: AP dict
         :param stas: STA dict
        """
        mp.Process.__init__(self)
        self._ssid = ssid
        self._dev = dev
        self._conn = conn
        self._err = None
        self._oinfo = None  # the original device info
        self._ocard = None  # the orginal card
        self._ncard = None  # the new card
        self._setup()

    def run(self):
        """ execution loop """
        # ececution loop
        while True:
            if self._conn.poll():
                tkn = self._conn.recv()
                if tkn == '!QUIT!': break

        if not self._teardown():
            self._conn.send(('!ERR!',self._err))
        self._conn.close()

    def _setup(self):
        """ setup radio and tuning thread """
        # set up the radio for collection
        try:
            # store the old card and create a new one, deleting any assoc interfaces
            self._oinfo = pyw.devinfo(self._dev)
            self._ocard = self._oinfo['card']
            self._ncard = pyw.devadd(self._ocard,'capt0','monitor')
            for card, _ in pyw.ifaces(self._ncard):
                if card.dev != self._ncard.dev: pyw.devdel(card)
            if not pyw.isup(self._ncard): pyw.up(self._ncard)
        except pyric.error as e:
            raise RuntimeError("ERRNO {0} {1}".format(e.errno, e.strerror))

    def _teardown(self):
        """ restore radio and wait on tuning thread"""
        # teardown the radio
        clean = True
        try:
            if self._ncard:
                self._ocard = pyw.devadd(self._ncard,self._dev,self._oinfo['mode'])
                pyw.devdel(self._ncard)
                if not pyw.isup(self._ocard): pyw.up(self._ocard)
        except pyric.error as e:
            clean = False
            self._err = "ERRNO {0} {1}".format(e.errno, e.strerror)
        return clean
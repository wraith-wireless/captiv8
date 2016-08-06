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

Provides the Collector and Tuner class

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
import threading
from Queue import Queue as TQ, Empty as qempty
import time
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as channels

BLOCK = 0.200

class Tuner(threading.Thread):
    """ tunes radio """
    def __init__(self,q,card,scan):
        """
         tunes card
         :param q: the token queue
         :param card: the card/radio to tune
         :param scan: scan list of available channels, a list of tuples
          t = (rf, channel width)
        """
        threading.Thread.__init__(self)
        self._card = card
        self._scan = scan
        self._q = q

    def run(self):
        # we'll pull out scan to avoid calling it every BLOCK seconds
        i = 0
        scan = self._scan
        n = len(self._scan)

        # create netlink socket and run through the scan list
        nlsock = nl.nl_socket_alloc()
        while True:
            # block on the q for BLOCK seconds, if no token, change the channel
            try:
                tkn = self._q.get(True,BLOCK)
                if tkn == '!QUIT!': break
            except qempty:
                i = (i+1) % n
                try:
                    pyw.freqset(self._card,scan[i][0],scan[i][1],nlsock)
                except pyric.error:
                    pass
        nl.nl_socket_free(nlsock)


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
        self._ssid = ssid   # ssid to scan for
        self._dev = dev     # radio
        self._conn = conn   # connecion to captiv
        self._tc = None     # connection to tuner
        self._tuner = None  # tuner thread
        self._err = None    # err message
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
        nlsock = None
        try:
            # get a netlink socket for this
            nlsock = nl.nl_socket_alloc()

            # store the old card and create a new one, deleting any assoc interfaces
            self._oinfo = pyw.devinfo(self._dev,nlsock)
            self._ocard = self._oinfo['card']
            self._ncard = pyw.devadd(self._ocard,'cap8','monitor',None,nlsock)
            for card, _ in pyw.ifaces(self._ncard,nlsock):
                if card.dev != self._ncard.dev: pyw.devdel(card,nlsock)
            if not pyw.isup(self._ncard): pyw.up(self._ncard)

            # determine scannable channels, then go to first channel
            scan = []
            for rf in pyw.devfreqs(self._ncard,nlsock):
                for chw in channels.CHTYPES:
                    try:
                        pyw.freqset(self._ncard,rf,chw,nlsock)
                    except pyric.error:
                        pass
                    else:
                        scan.append((rf, chw))
            assert scan
            pyw.freqset(self._ncard,scan[0][0],scan[0][1])

            # start the tuner
            self._q = TQ()
            self._tuner = Tuner(self._q,self._ncard,scan)
            self._tuner.start()
        except (threading.ThreadError,RuntimeError):
            self._teardown()
            raise RuntimeError("Unexepected error in the tuner")
        except AssertionError:
            self._teardown()
            raise RuntimeError("No valid scan channels found")
        except nl.error as e:
            self._teardown()
            raise RuntimeError("ERRNO {0} {1}".format(e.errno, e.strerror))
        except pyric.error as e:
            self._teardown() # attempt to restore
            raise RuntimeError("ERRNO {0} {1}".format(e.errno, e.strerror))
        finally:
            nl.nl_socket_free(nlsock)

    def _teardown(self):
        """ restore radio and wait on tuning thread"""
        clean = True

        # start with the tuner
        self._tuner.join(5.0)

        # then restore the radio
        try:
            if self._ncard:
                self._ocard = pyw.devadd(self._ncard,self._dev,self._oinfo['mode'])
                pyw.devdel(self._ncard)
                if not pyw.isup(self._ocard): pyw.up(self._ocard)
        except pyric.error as e:
            clean = False
            self._err = "ERRNO {0} {1}".format(e.errno, e.strerror)
        if threading.active_count() > 0:
            clean = False
            self._err = "Tuner failed to stop"
        self._conn.close()
        return clean
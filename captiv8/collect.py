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
from Queue import Empty
import select as sselect # rename, scapy is intefering
import socket
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as channels
import logging                                             # import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # to hide ipv6 warning
import scapy.all as scapy

SCAN  = 0.2
SNIFF = 0.4

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
        # we'll pull out scan to avoid calling it every SCAN seconds
        i = 0
        scan = self._scan
        n = len(self._scan)

        # create netlink socket and run through the scan list
        nlsock = nl.nl_socket_alloc()
        while True:
            # block on the q for SCAN seconds, if no token, change the channel
            try:
                tkn = self._q.get(True,SCAN)
                if tkn == '!QUIT!': break
            except Empty:
                i = (i+1) % n
                try:
                    pyw.freqset(self._card,scan[i][0],scan[i][1],nlsock)
                except pyric.error:
                    pass
        nl.nl_socket_free(nlsock)

class Sniffer(threading.Thread):
    """ sniffs packets """
    def __init__(self,tq,pq,dev):
        """
         initialize sniffer
         :param tq: token queue
         :param pq: packet queue
         :param dev: the interface to sniff packets from
        """
        threading.Thread.__init__(self)
        self._tq = tq
        self._pq = pq
        self._s = None
        self._setup(dev)

    def run(self):
        while True:
            try:
                tkn = self._tq.get_nowait()
                if tkn == '!QUIT!': break
            except Empty:
                # scapy pickles the callback which leads to errors if the
                # the callback is not module level - so we read the raw packet
                try:
                    pkt = self._s.recv(7935)
                    self._pq.put(pkt)
                except socket.timeout:
                    pass
        self._teardown()

    def _setup(self,dev):
        try:
            self._s = socket.socket(socket.AF_PACKET,
                                    socket.SOCK_RAW,
                                    socket.htons(0x0003))
            self._s.settimeout(SNIFF)
            self._s.bind((dev,0x0003))
        except socket.error as e:
            raise RuntimeError(e)

    def _teardown(self):
        if self._s: self._s.close()
        self._s = None

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
        self._ssid = ssid    # ssid to scan for
        self._dev = dev      # device name
        self._conn = conn    # connecion to captiv
        self._aps = aps      # AP dict
        self._stas = stas    # STA dict
        self._tknq = None    # token queue
        self._pktq = None    # packet queue
        self._tuner = None   # tuner thread
        self._sniffer = None # the sniffer thread
        self._err = None     # err message
        self._card = None    # the card to use
        self._mode = None    # card's orginal mode
        self._setup()

    def run(self):
        """ execution loop """
        # ececution loop
        self._tuner.start()
        self._sniffer.start()
        stop = False
        while not stop:
            try:
                rs,_,_ = sselect.select([self._conn,self._pktq._reader],[],[],1)
                for r in rs:
                    try:
                        if r == self._conn:
                            tkn = self._conn.recv()
                            if tkn == '!QUIT!': stop = True
                        else:
                            self._processpkt()
                    except Exception as e:
                        # catchall
                        self._conn.send('!ERR',"{0} {1}".format(type(e).__name__,e))
                        break
            except sselect.error as e:
                if e[0] == 4: continue
                else:
                    self._conn.send('!ERR',"{0} {1}".format(type(e).__name__,e))
                    break
        if not self._teardown(): self._conn.send(('!ERR!',self._err))
        self._conn.send(('!AP!',self._aps))
        self._conn.close()

    def _processpkt(self):
        """ pulls a packet of the queue and processes it """
        pkt = self._pktq.get()
        pkt = scapy.RadioTap(pkt)
        if not pkt.haslayer(scapy.Dot11): return
        if pkt.type == 0: # mgmt
            if pkt.subtype == 8: # beacon
                if pkt.info == self._ssid:
                    if not pkt.addr2 in self._aps:
                        self._aps[pkt.addr2] = True

    def _setup(self):
        """ setup radio and tuning thread """
        # set up the radio for collection
        nlsock = None
        try:
            # get a netlink socket for this
            nlsock = nl.nl_socket_alloc()

            # store the old card and create a new one, deleting any assoc interfaces
            self._card = pyw.getcard(self._dev,nlsock)
            self._mode = pyw.modeget(self._card,nlsock)

            if self._mode != 'monitor':
                pyw.down(self._card)
                pyw.modeset(self._card,'monitor',None,nlsock)
                pyw.up(self._card)

            # determine scannable channels, then go to first channel
            scan = []
            for rf in pyw.devfreqs(self._card,nlsock):
                for chw in channels.CHTYPES:
                    try:
                        pyw.freqset(self._card,rf,chw,nlsock)
                    except pyric.error:
                        pass
                    else:
                        scan.append((rf, chw))
            assert scan
            pyw.freqset(self._card,scan[0][0],scan[0][1])

            # create the tuner & sniffer
            self._tknq = mp.Queue()
            self._pktq = mp.Queue()
            self._tuner = Tuner(self._tknq,self._card,scan)
            self._sniffer = Sniffer(self._tknq,self._pktq,self._dev)
        except RuntimeError as e:
            self._teardown()
            raise RuntimeError("Error binding socket {0}".format(e))
        except threading.ThreadError as e:
            self._teardown()
            raise RuntimeError("Unexepected error in the workers {0}".format(e))
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

        # notify the workers to stop
        try:
            for _ in range(threading.active_count()): self._tknq.put('!QUIT!')
            if self._tuner: self._tuner.join(5.0)
            if self._sniffer: self._sniffer.join(5.0)
        except IOError as e:
            # something failed with the queue
            clean = False
            self._err = "Error stopping workers {0}".format(e.strerror)

        try:
            # then restore the radio
            if self._card and self._mode != 'monitor':
                pyw.down(self._card)
                pyw.modeset(self._card,self._mode)
                pyw.up(self._card)

            # check if tuner has quit
            if threading.active_count() > 0:
                clean = False
                self._err = "One or more workers failed to stop"
        except pyric.error as e:
            clean = False
            self._err = "ERRNO {0} {1}".format(e.errno, e.strerror)
        except IOError as e:
            clean = False
            self._err = "Failed to close comms {0}".format(e.strerror)
        return clean
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
__version__ = '0.0.2'
__date__ = 'August 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import multiprocessing as mp
import threading
import select
import socket
import time
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as channels
import itamae.radiotap as rtap
import itamae.mpdu as mpdu

SCAN  = 0.2

class Tuner(threading.Thread):
    """ tunes radio """
    def __init__(self,card,scan):
        """
         tunes card
         :param card: the card/radio to tune
         :param scan: scan list of available channels, a list of tuples
          t = (rf, channel width)
        """
        threading.Thread.__init__(self)
        self._card = card
        self._scan = scan

    def run(self):
        # we'll pull out scan & card to avoid calling it every SCAN seconds
        i = 0
        card = self._card
        scan = self._scan
        n = len(self._scan)

        # loop until the card is destroyed. we'll use pyric.error as
        # a poison pill
        nlsock = nl.nl_socket_alloc()
        while True:
            try:
                time.sleep(SCAN)
                i = (i + 1) % n
                pyw.freqset(card, scan[i][0], scan[i][1], nlsock)
            except pyric.error:
                # ideally we should check below and return error if
                # we didn't lose the card
                #if not pyw.validcard(card,nlsock): break
                break
        nl.nl_socket_free(nlsock)

class Sniffer(threading.Thread):
    """ sniffs packets """
    def __init__(self,pq,dev):
        """
         initialize sniffer
         :param pq: packet queue
         :param dev: the interface to sniff packets from
        """
        threading.Thread.__init__(self)
        self._pq = pq
        self._s = None
        self._setup(dev)

    def run(self):
        s = self._s
        q = self._pq
        try:
            while True:
                frame = s.recv(7935)
                q.put(frame)
        except socket.error: # assume any socket error means the Card is closed
            self._teardown()

    def _setup(self,dev):
        try:
            self._s = socket.socket(socket.AF_PACKET,
                                    socket.SOCK_RAW,
                                    socket.htons(0x0003))
            self._s.bind((dev,0x0003))
        except socket.error as e:
            raise RuntimeError(e)

    def _teardown(self):
        if self._s: self._s.close()
        self._s = None

# noinspection PyCallByClass
class Collector(mp.Process):
    """ Collects data on wireless nets """
    def __init__(self,conn,dq,ssid,dev,aps,stas):
        """
         initialize Collector
         :param conn: pipe connection
         :param dq: data queue
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
        self._datq = dq      # data queue
        self._pktq = None    # packet queue
        self._tuner = None   # tuner thread
        self._sniffer = None # the sniffer thread
        self._err = None     # err message
        self._dinfo = None   # dev's original info
        self._card = None    # the card to use
        self._setup()

    def terminate(self):
        """ override terminate """
        self._teardown()
        mp.Process.terminate(self)

    def run(self):
        """ execution loop """
        # start our threads
        self._tuner.start()
        self._sniffer.start()

        # set up our inputs list for select & stop token
        # noinspection PyProtectedMember
        ins = [self._conn,self._pktq._reader]
        stop = False

        while not stop:
            try:
                rs,_,_ = select.select(ins,[],[],1)
                for r in rs:
                    if r == self._conn:
                        tkn = self._conn.recv()
                        if tkn == '!QUIT!': stop = True
                    else:
                        self._processpkt()
            #except Exception as e:
            #    # catchall
            #    self._conn.send(('!ERR',"{0} {1}".format(type(e).__name__,e)))
            #    stop = True
            except select.error as e:
                if e[0] != 4:
                    self._conn.send(('!ERR',"{0} {1}".format(type(e).__name__,e)))
                    stop = True
        if not self._teardown():
            self._conn.send(('!ERR!',self._err))

    def _processpkt(self):
        """
         pulls a packet of the queue and processes it. Sends notification of
         new APs found and notifications of new STAs or STAs with updated
         timestamps
        """
        # get the packet off the queue, parse it. Return if no Dot11
        pkt = self._pktq.get()
        dR = rtap.parse(pkt)
        dM = mpdu.parse(pkt[dR.sz:],'fcs' in dR.flags)
        if dM.error: return

        if dM.type == 0: # mgmt
            # for BSSIDs, look at beacon, assoc request, and probe response
            if dM.subtype == 8 or dM.subtype == 0 or dM.subtype == 5:
                ssids, = dM.getie([mpdu.EID_SSID])
                if self._ssid in ssids:
                    if not dM.addr3 in self._aps:
                        self._aps[dM.addr3] = dR.rss
                        self._datq.put(('!AP-new!',(dM.addr3,self._aps[dM.addr3])))
                    else:
                        self._aps[dM.addr3] = dR.rss
                        self._datq.put(('!AP-upd!',(dM.addr3,self._aps[dM.addr3])))
        elif dM.type == 2: # data
            rss = None
            if dM.flags['td'] and not dM.flags['fd']:
                bssid = dM.addr1
                sta = dM.addr2
                rss = dR.rss
            elif not dM.flags['td'] and dM.flags['fd']:
                bssid = dM.addr2
                sta = dM.addr1
            else:
                return

            # do nothing if we got a broadcast
            if sta == "ff:ff:ff:ff:ff:ff": return

            # if we have a matching bssid proceed
            if bssid in self._aps:
                if not sta in self._stas:
                    self._stas[sta] = {'ASW':bssid,
                                       'ts':time.time(),
                                       'rf':dR.channel,
                                       'rss':rss}
                    self._datq.put(('!STA-new!',(sta,self._stas[sta])))
                else:
                    self._stas[sta]['ts'] = time.time()
                    self._stas[sta]['rf'] = dR.channel
                    if rss: self._stas[sta]['rss'] = rss
                    self._datq.put(('!STA-upd!',(sta,self._stas[sta])))

    def _setup(self):
        """ setup radio and tuning thread """
        # set up the radio for collection
        nlsock = None
        try:
            # get a netlink socket for this
            nlsock = nl.nl_socket_alloc()

            # get dev info for dev and it's phy index
            self._dinfo = pyw.devinfo(self._dev,nlsock)
            phy = self._dinfo['card'].phy

            # delete all associated interfaces
            for c,_ in pyw.ifaces(self._dinfo['card'],nlsock): pyw.devdel(c,nlsock)

            # create a new card in monitor mode
            self._card = pyw.phyadd(phy,'cap8','monitor',None,nlsock)
            pyw.up(self._card)

            # determine scannable channels, then go to first channel
            scan = []
            for rf in pyw.devfreqs(self._card,nlsock):
                for chw in channels.CHTYPES:
                    try:
                        pyw.freqset(self._card,rf,chw,nlsock)
                        scan.append((rf, chw))
                    except pyric.error as e:
                        if e.errno != pyric.EINVAL: raise
            assert scan
            pyw.freqset(self._card,scan[0][0],scan[0][1],nlsock)

            # create the tuner & sniffer
            self._pktq = mp.Queue()
            self._tuner = Tuner(self._card,scan)
            self._sniffer = Sniffer(self._pktq,self._card.dev)
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
        self._err = ""

        # restore the radio - this will have the side effect of
        # causing the threads to error out and quit
        try:
            if self._card:
                phy = self._card.phy
                pyw.devdel(self._card)
                card = pyw.phyadd(phy,self._dev,self._dinfo['mode'])
                pyw.up(card)
        except pyric.error as e:
            clean = False
            self._err = "ERRNO {0} {1}".format(e.errno, e.strerror)

        # join threads, waiting a short time before continuing
        try:
            self._tuner.join(5.0)
        except (AttributeError,RuntimeError):
            # either tuner is None, or it never started
            pass

        try:
            self._sniffer.join(5.0)
        except (AttributeError, RuntimeError):
            # either sniffer is None, or it never started
            pass

        if threading.active_count() > 0:
            clean = False
            self._err += "One or more workers failed to stop"

        return clean
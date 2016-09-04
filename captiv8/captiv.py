#!/usr/bin/env python

""" capitv.py: Captive Portal Evasion Tool interface

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

Provides the user interface to captiv8
"""

#__name__ = 'capitv'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import curses
import curses.ascii as ascii
import multiprocessing as mp
from Queue import Empty
import threading
import time
import os, sys
import pyric
import pyric.pyw as pyw
from pyric.utils.channels import rf2ch,ch2rf
import pyric.net.if_h as ifh
import captiv8
import captiv8.collect as collect

#### CONSTANTS

# MAIN WINDOW BANNER
_BANNER_ = [
"   ___     _____   _____  _______  _______  _     _   _____",
" _(___)_  (_____) (_____)(__ _ __)(_______)(_)   (_) (_____)",
"(_)   (_)(_)___(_)(_)__(_)  (_)      (_)   (_)   (_)(_)___(_)",
"(_)    _ (_______)(_____)   (_)      (_)   (_)   (_) (_____)",
"(_)___(_)(_)   (_)(_)       (_)    __(_)__  (_)_(_) (_)___(_)",
"  (___)  (_)   (_)(_)       (_)   (_______)  (___)   (_____)",
]

# PROGRAM STATE DEFINITIONS
_INVALID_     = 0
_CONFIGURED_  = 1
_SCANNING_    = 2
_STOPPED_     = 3
_CONNECTING_  = 4
_CONNECTED_   = 5
_GETTINGIP_   = 6
_VERIFYING_   = 7
_OPERATIONAL_ = 8
_QUITTING_    = 9
_STATE_FLAG_NAMES_ = [
    'invalid    ',
    'configured ',
    'scanning   ',
    'stopped    ',
    'connecting ',
    'connected  ',
    'gettingip  ',
    'verifying  ',
    'operational',
    'quitting   ']

# FIXED LENGTHS
_IPLEN_   = 15
_DEVLEN_  = ifh.IFNAMSIZ
_MACLEN_  = 17
_SSIDLEN_ = 32
_FIXLEN_  = 10 # arbitrary fixed field length of 10

# COLORS & COLOR PAIRS
COLORS = 14
BLACK,RED,GREEN,YELLOW,BLUE,MAGENTA,CYAN,WHITE,GRAY,BUTTON,HLITE,ERR,WARN,NOTE = range(COLORS)
CPS = [None] * COLORS

#### errors
class error(EnvironmentError): pass

#### status update thread

class InfoUpdateThread(threading.Thread):
    """ updates Info Window status symbol/statement """
    def __init__(self,win,block,state,iws):
        """
         initialize thread
         :param win: the info window
         :param block: blocking event
         :param state: state dictionary
         :param iws: the info window output dict should have the following keys:
           'current', 'current-msg'
        """
        threading.Thread.__init__(self)
        self._win = win
        self._hold = block
        self._state = state
        self._iws = iws

    def run(self):
        """ write current state symbol and info """
        i = 0
        symbol = color = None

        # loop until it's time to exit
        while True:
            self._hold.wait()
            s = self._state['state']
            if s == _QUITTING_: return
            if s == _INVALID_ or s == _CONFIGURED_:
                color = CPS[RED]
                symbol = '?' if s == _INVALID_ else '-'
            elif s == _OPERATIONAL_:
                color = CPS[GREEN]
                symbol = '+'
            elif s == _QUITTING_:
                color = CPS[GREEN]
                symbol = '#'
            elif s > _CONFIGURED_:
                color = CPS[YELLOW]
                symbol = '/' if i else '\\'
                i = (i+1) % 2
            self._win.addch(self._iws['current'][0],
                             self._iws["current"][1],
                             symbol,color)
            self._win.addstr(self._iws['current-msg'][0],
                             self._iws['current-msg'][1],
                             _STATE_FLAG_NAMES_[s],CPS[WHITE])
            self._win.refresh()
            time.sleep(0.1)

class DataUpdateThread(threading.Thread):
    """ updates Data dicts and message """
    def __init__(self,win,block,dq,nets,state,iws):
        """
         initialize thread
         :param win: the info window
         :param block: blocking event
         :param dq: data queue
         :param nets: network dict
         :param state: state dict
         :param iws: the info window output dict should have the following keys:
           'data-msg'
        """
        threading.Thread.__init__(self)
        self._win = win
        self._hold = block
        self._dq = dq
        self._nets = nets
        self._state = state
        self._iws = iws

    def run(self):
        # loop until it's time to exit
        while True:
            self._hold.wait()
            s = self._state['state']
            if s == _QUITTING_: return
            while True:
                try:
                    # get the next message and clear the data message field
                    tkn,data = self._dq.get_nowait()
                    self._win.addstr(self._iws['data-msg'][0],
                                     self._iws['data-msg'][1],
                                     ' '*self._iws['data-msg'][2],
                                     CPS[WHITE])

                    # process the token
                    if tkn == '!AP-new!':
                        bssid,rss = data
                        self._nets[bssid] = {'ch':None,'rss':rss,'stas':{}}
                        msg = "Found AP w/ BSSID {0}. Total = {1}"
                        msg = msg.format(bssid,len(self._nets))
                        self._win.addstr(self._iws['data-msg'][0],
                                         self._iws['data-msg'][1],
                                         msg,CPS[WHITE])
                    elif tkn == '!AP-upd!':
                        bssid,rss = data
                        self._nets[bssid]['rss'] = rss
                    elif tkn == '!STA-new!':
                        sta,sinfo = data
                        bssid = sinfo['ASW']
                        self._nets[bssid]['stas'][sta] = {
                            'ts':sinfo['ts'],
                            'rss':sinfo['rss'],
                            'spoofed':0,
                            'success':0,
                        }
                        self._nets[bssid]['ch'] = rf2ch(sinfo['rf'])
                        msg = "Found STA {0} ASW BSSID {1}".format(sta,sinfo['ASW'])
                        self._win.addstr(self._iws['data-msg'][0],
                                         self._iws['data-msg'][1],
                                         msg,CPS[WHITE])
                    elif tkn == '!STA-upd!':
                        sta,sinfo = data
                        bssid = sinfo['ASW']
                        self._nets[bssid]['stas'][sta]['ts'] = sinfo['ts']
                        self._nets[bssid]['stas'][sta]['rss'] = sinfo['rss']
                        self._nets[bssid]['ch'] = rf2ch(sinfo['rf'])
                    self._win.refresh()
                except Empty:
                    time.sleep(0.5)
                    break

#### INIT/DEINIT

def setup():
    """
     sets environment up and creates main window
     :returns: the main window object
    """
    # setup the console
    mmask = curses.ALL_MOUSE_EVENTS # for now accept all mouse events
    main = curses.initscr()         # get a window object
    y,x = main.getmaxyx()           # get size
    if y < 24 or x < 80:            # verify minimum size rqmts
        raise RuntimeError("Terminal must be at least 80 x 24")
    curses.noecho()                 # turn off key echoing
    curses.cbreak()                 # turn off key buffering
    curses.mousemask(mmask)         # accept mouse events
    initcolors()                    # turn on and set color pallet
    main.keypad(1)                  # let curses handle multibyte special keys
    main.clear()                    # erase everything
    banner(main)                    # write the banner
    mainmenu(main)                  # then the min and menu
    main.attron(CPS[RED])           # make the border red
    main.border(0)                  # place the border
    main.attroff(CPS[RED])          # turn off the red
    curses.curs_set(0)              # hide the cursor
    main.refresh()                  # and show everything
    return main

def teardown(win):
    """
     returns console to normal state
     :param win: the window
    """
    # tear down the console
    curses.nocbreak()
    if win: win.keypad(0)
    curses.echo()
    curses.endwin()

def initcolors():
    """ initialize color pallet """
    curses.start_color()
    if not curses.has_colors():
        raise RuntimeError("Sorry. Terminal does not support colors")

    # setup colors on black background
    for i in range(1,9):
        curses.init_pair(i,i,BLACK)
        CPS[i] = curses.color_pair(i)

    # have to individually set up special cases
    curses.init_pair(BUTTON,WHITE,GRAY)     # white on gray for buttons
    CPS[BUTTON] = curses.color_pair(BUTTON)
    curses.init_pair(HLITE,BLACK,GREEN)     # black on Green for highlight aps,stas
    CPS[HLITE] = curses.color_pair(HLITE)
    curses.init_pair(ERR,WHITE,RED)         # white on red
    CPS[ERR] = curses.color_pair(ERR)
    curses.init_pair(WARN,BLACK,YELLOW)     # white on yellow
    CPS[WARN] = curses.color_pair(WARN)
    curses.init_pair(NOTE,WHITE,GREEN)      # white on red
    CPS[NOTE] = curses.color_pair(NOTE)

def banner(win):
    """
     writes the banner (caller will need to refresh)
     :param win: main window
    """
    # get the num columns and the longest banner length to find the start column
    _,nc = win.getmaxyx()
    c = 0
    for line in _BANNER_:
        if len(line) > c: c = len(line)
    c = (nc-c)/2

    # add each line in the banner
    for i,line in enumerate(_BANNER_): win.addstr(i+1,c,line,CPS[WHITE])

    # put the copyright in the middle
    copy = "captiv8 v{0} Copyright {1}".format(captiv8.version,captiv8.__date__)
    win.addstr(len(_BANNER_)+1,(nc-len(copy))/2,copy,CPS[BLUE])

#### WIDGETS SETUP

def mainmenu(win,s=None):
    """
     writes the main menu (caller will need to refresh)
     :param win: the main window
     :param s: current state, None = invalid
    """
    start = len(_BANNER_)+2
    win.addstr(start,3, "MENU: choose one",CPS[BLUE])

    # for each option, set color based on state
    # configure
    color = CPS[WHITE]
    if s == _SCANNING_ or _CONNECTING_ <= s < _OPERATIONAL_:
        color = CPS[GRAY]
    win.addstr(start+1,5,"[C|c]onfigure",color)

    # run
    if s == _SCANNING_:
        text = "[S|s]top"
        color = CPS[WHITE]
    else:
        text = "[R|r]un " # add a space to cover Stop
        if s == _CONFIGURED_ or s == _STOPPED_:
            color = CPS[WHITE]
        else:
            color = CPS[GRAY]
    win.addstr(start+2,5,text,color)

    # view
    color = CPS[WHITE]
    if s < _SCANNING_: color = CPS[GRAY]
    win.addstr(start+3,5,"[V|v]iew",color)

    # quit is always allowed
    win.addstr(start+4,5,"[Q|q]uit",CPS[WHITE])

def infowindow(win):
    """
     create an info window as derived window of main window win
    :param win: main window
    :returns: tuple t = (info window, info window outputs)
    """
    # add a derived window center bottom with 9 rows, & a blue border
    nr,nc = win.getmaxyx()
    info = win.derwin(9,nc-4,nr-10,2)
    y,x = info.getmaxyx()
    info.attron(CPS[BLUE])
    info.border(0)
    info.attron(CPS[BLUE])

    # init to None the info window outputs dict
    # iws = field -> (start_y, start_x,length)
    iws = {'dev':None,'Driver':None,'Mode':None,      # source fields
           'MAC':None,'Manuf':None,'Connected':None,
           'SSID':None,'BSSID':None,                  # target fields
           'STA:':None,'IP':None}

    # add source info labels
    info.addstr(0,x-len('SOURCE')-1,'SOURCE',CPS[WHITE])
    row1 = "dev: {0} Driver: {1} Mode: {1}".format('-'*_DEVLEN_,'-'*_FIXLEN_)
    row2 = "MAC: {0} Manuf: {1} Connected: -".format('-'*_MACLEN_,'-'*_FIXLEN_)
    info.addstr(1,1,row1,CPS[WHITE])
    info.addstr(2,1,row2,CPS[WHITE])

    # add window output fields
    # row 1
    r = len('dev: ')+1
    iws['dev'] = (1,r,_DEVLEN_)
    r += _DEVLEN_ + len(" Driver: ")
    iws['Driver'] = (1,r,_FIXLEN_)
    r += _FIXLEN_ + len(" Mode: ")
    iws['Mode'] = (1,r,_FIXLEN_)
    # row 2
    r = len("MAC: ")+1
    iws['MAC'] = (2,r,_MACLEN_)
    r += _MACLEN_ + len(" Manuf: ")
    iws['Manuf'] = (2,r,_FIXLEN_)
    r += _FIXLEN_ + len(" Connected: ")
    iws['Connected'] = (2,r,1)

    # add a horz. line seperating the source and target info panels
    info.hline(3,1,curses.ACS_HLINE,x-2)
    info.addstr(3,x-len('TARGET')-1,'TARGET',CPS[WHITE])

    # add our target info labels
    info.addstr(4,1,"SSID:",CPS[WHITE])
    info.addstr(4,7,'-'*_SSIDLEN_,CPS[WHITE])
    iws['SSID'] = (4,7,_SSIDLEN_)
    info.addstr(4,x-(len("BSSID: ")+_MACLEN_+1),"BSSID:",CPS[WHITE])
    info.addstr(4,x-(_MACLEN_+1),'-'*_MACLEN_,CPS[WHITE])
    iws['BSSID'] = (4,x-(_MACLEN_+1),_MACLEN_)
    info.addstr(5,1,"STA:",CPS[WHITE])
    info.addstr(5,7,'-'*_MACLEN_,CPS[WHITE])
    iws['STA'] = (5,7,_MACLEN_)
    info.addstr(5,x-(len("IP: ")+_MACLEN_+1),"IP:",CPS[WHITE]) # right align w/ BSSID
    info.addstr(5,x-(_IPLEN_+1),'-'*_IPLEN_,CPS[WHITE])
    iws['IP'] = (5,x-(_IPLEN_+1),_IPLEN_)

    # add the current status at bottom left
    info.addstr(6,1,"[ ] {0}".format(_STATE_FLAG_NAMES_[_INVALID_]),CPS[WHITE])
    info.addch(6,2,ord('?'),CPS[RED])
    iws['current'] = (6,2,1)
    iws['current-msg'] = (6,len("[ ] ")+1,x-len("[ ] ")-2)
    iws['data-msg'] = (7,1,x-2)
    info.refresh()
    return info, iws

def updatesourceinfo(win,iws,c):
    """
     writes current state to info window
     :param win: the info window
     :param iws: the info window output dict should at minimum the keys
            'dev','Driver','Mode','MAC','Manuf','Connected',
     :param c: the current config should be in the form
      config = {'SSID':None, 'dev':None, 'connect':None}
    """
    # set defaults then check the conf dict for a device
    dev = c['dev'] if c['dev'] else '-'*_DEVLEN_
    driver = mode = manuf = '-'*_FIXLEN_
    hwaddr = '-'*_MACLEN_
    conn = '-'
    color = CPS[WHITE]
    if c['dev']:
        try:
            card = pyw.getcard(dev)
            ifinfo = pyw.ifinfo(card)
            driver = ifinfo['driver'][:_FIXLEN_] # trim excess
            hwaddr = ifinfo['hwaddr'].upper()
            manuf = ifinfo['manufacturer'][:_FIXLEN_] # trim excess
            mode = pyw.modeget(card)
            conn = 'Y' if pyw.isconnected(card) else 'N'
            color = CPS[GREEN]
        except pyric.error as _e:
            raise error("ERRNO {0}. {1}".format(_e.errno,_e.strerror))
    win.addstr(iws['dev'][0],iws['dev'][1],dev,color)
    win.addstr(iws['Driver'][0],iws['Driver'][1],driver,color)
    win.addstr(iws['Mode'][0],iws['Mode'][1],mode,color)
    win.addstr(iws['MAC'][0],iws['MAC'][1],hwaddr,color)
    win.addstr(iws['Manuf'][0],iws['Manuf'][1],manuf,color)
    win.addstr(iws['Connected'][0],iws['Connected'][1],conn,color)

def updatetargetinfo(win,iws,c):
    """
     writes current state to info window
     :param win: the info window
     :param iws: the info window output dict should have at minimum the keys
           'SSID','BSSID','STA','IP'
     :param c: the current config should be in the form
      config = {'SSID':None, 'dev':None, 'connect':None}
    """
    # TODO: have to also pass data concerning any BSSID/STA/IP data once
    # connected
    # overwrite old ssid with blanks before writing new
    win.addstr(iws['SSID'][0],iws['SSID'][1],'-'*_SSIDLEN_,CPS[WHITE])
    if c['SSID']: win.addstr(iws['SSID'][0],iws['SSID'][1],c['SSID'],CPS[GREEN])

# noinspection PyUnresolvedReferences
def updatestateinfo(win,iws,s):
    """
     writes current state to info window
     :param win: the info window
     :param iws: the info window output dict should have at minimun the keys
           'current','current-msg'
     :param s: current state
    """
    color = symbol = None # appease pycharm
    if s == _INVALID_ or s == _CONFIGURED_:
        color = CPS[RED]
        symbol = '?' if s == _INVALID_ else '-'
    elif s == _OPERATIONAL_:
        color = CPS[GREEN]
        symbol = '+'
    elif s == _QUITTING_:
        color = CPS[GREEN]
        symbol = '#'
    elif s > _CONFIGURED_:
        color = CPS[YELLOW]
        symbol = '/'
    win.addch(iws['current'][0],iws["current"][1],symbol,color)
    win.addstr(iws['current-msg'][0],iws['current-msg'][1],_STATE_FLAG_NAMES_[s],CPS[WHITE])
    win.refresh()

# noinspection PyUnresolvedReferences
def msgwindow(win,mtype,msg):
    """
     shows an error/warning/note msg until user clicks OK
     :param win: the main window
     :param mtype: message type one of {'err','warn','note'}
     :param msg: the message to display
    """
    # set max width & line width
    nx = 30
    llen = nx -2

    # break the message up into lines
    lines = []
    line = ''
    for word in msg.split(' '):
        if len(word) + 1 + len(line) > llen:
            lines.append(line.strip())
            line = word
        else:
            line += ' ' + word
    if line: lines.append(line)

    # now calcuate # of rows needed
    ny = 4 + len(lines) # 2 for border, 2 for title/btn)

    # determine color scheme and title (set default as error
    title = "ERROR"
    color = ERR
    if mtype == 'warn':
        title = "WARNING"
        color = WARN
    elif mtype == 'note':
        title = "NOTE"
        color = NOTE

    # create the msg window
    nr,nc = win.getmaxyx()
    zy = (nr-ny)/2
    zx = (nc-nx)/2
    msgwin = curses.newwin(ny,nx,zy,zx)
    msgwin.bkgd(' ',CPS[color])
    msgwin.attron(color)
    msgwin.border(0)

    # display title, message and OK btn
    msgwin.addstr(1,(llen-len(title))/2,title)
    for i,line in enumerate(lines): msgwin.addstr(i+2,1,line)
    btn = "Ok"
    btncen = (nx-len(btn))/2
    by,bx = ny-2,btncen-(len(btn)-1)
    msgwin.addstr(by,bx,btn[0],CPS[BUTTON]|curses.A_UNDERLINE)
    msgwin.addstr(by,bx+1,btn[1:],CPS[BUTTON])
    bs = (by+zy,bx+zx,2)

    # show the win, and take keypad & loop until OK'd
    msgwin.refresh()
    msgwin.keypad(1)
    while True:
        _ev = msgwin.getch()
        if _ev == curses.KEY_MOUSE:
            try:
                _,mx,my,_,b = curses.getmouse()
                if b == curses.BUTTON1_CLICKED:
                    if my == bs[0] and (bs[1] <= mx <= bs[1] + bs[2]): break
            except curses.error:
                continue
        else:
            try:
                _ch = chr(_ev).upper()
            except ValueError:
                continue
            if _ch == 'O': break
    del msgwin
    win.touchwin()
    win.refresh()

def waitwindow(win,ttl,msg):
    """
     displays a blocking window w/ message
     :param win: the main window
     :param ttl: the title (must be less than nx)
     :param msg: the message
     :returns: the wait window
    """
    # set max width & line width
    nx = 30
    llen = nx -2

    # break the message up into lines
    lines = []
    line = ''
    for word in msg.split(' '):
        if len(word) + 1 + len(line) > llen:
            lines.append(line.strip())
            line = word
        else:
            line += ' ' + word
    if line: lines.append(line)

    # now calcuate # of rows needed
    ny = 3 + len(lines) # 2 for border, 1 for title)

    # create the wait window with a red border
    nr,nc = win.getmaxyx()
    zy = (nr-ny)/2
    zx = (nc-nx)/2
    waitwin = curses.newwin(ny,nx,zy,zx)
    waitwin.bkgd(' ',CPS[NOTE])
    waitwin.attron(NOTE)
    waitwin.border(0)

    # display title, message and OK btn
    ttl = ttl[:llen]
    waitwin.addstr(1,(llen-len(ttl))/2,ttl)
    for i,line in enumerate(lines): waitwin.addstr(i+2,1,line)

    # show the win, and take the keypad
    waitwin.refresh()
    waitwin.keypad(1)
    return waitwin

#### MENU OPTION CALLBACKS

# noinspection PyUnresolvedReferences
def configure(win,conf):
    """
     shows options to configure captiv8 for running
     :param win: the main window
     :param conf: current state of configuration dict
    """
    # create our on/off for radio buttons
    BON = curses.ACS_DIAMOND
    BOFF = '_'

    # create an inputs dict to hold the begin locations of inputs
    ins = {} # input -> (start_y,start_x,endx)

    # create a copy of conf to manipulate
    newconf = {}
    for c in conf: newconf[c] = conf[c]

    # create new window (new window will cover the main window)
    # get sizes for coord translation
    nr,nc = win.getmaxyx()               # size of the main window
    ny,nx = 15,50                        # size of new window
    zy,zx = (nr-ny)/2,(nc-nx)/2          # 0,0 (top left corner) of new window
    confwin = curses.newwin(ny,nx,zy,zx)

    # draw a blue border and write title
    confwin.attron(CPS[BLUE])
    confwin.border(0)
    confwin.attron(CPS[BLUE])
    confwin.addstr(1,1,"Configure Options",CPS[BLUE])

    # ssid option, add if present add a clear button to the right
    confwin.addstr(2,1,"SSID: " + '_'*_SSIDLEN_,CPS[WHITE])
    ins['SSID'] = (2+zy,len("SSID: ")+zx+1,len("SSID: ")+zx+_SSIDLEN_)
    if newconf['SSID']:
        for i,s in enumerate(newconf['SSID']):
            confwin.addch(ins['SSID'][0]-zy,ins['SSID'][1]-zx+i,s,CPS[GREEN])

    # allow for up to 6 devices to choose in rows of 2 x 3
    confwin.addstr(3,1,"Select dev:",CPS[WHITE]) # the sub title
    i = 4 # current row
    j = 0 # current dev
    devs = pyw.winterfaces()[:8]
    if not newconf['dev'] in devs: newconf['dev'] = None
    for dev in devs:
        stds = ""
        monitor = True
        nl80211 = True
        try:
            card = pyw.getcard(dev)
            stds = pyw.devstds(card)
            monitor = 'monitor' in pyw.devmodes(card)
        except pyric.error:
            # assume just related to current dev
            nl80211 = False
        devopt = "{0}. (_) {1}".format(j+1,dev)
        if stds: devopt += " IEEE 802.11{0}".format(''.join(stds))
        if monitor and nl80211:
            confwin.addstr(i,2,devopt,CPS[WHITE])
            ins[j] = (i+zy,len("n. (")+zx+2,len("n. (")+zx+3)
            if newconf['dev'] == dev:
                confwin.addch(ins[j][0]-zy,ins[j][1]-zx,BON,CPS[GREEN])
        else:
            # make it gray
            errmsg = ""
            if not monitor: errmsg = "No monitor mode"
            elif not nl80211: errmsg = "No nl80211"
            confwin.addstr(i,2,devopt,CPS[GRAY])
            confwin.addstr(i,3,'X',CPS[GRAY])
            confwin.addstr(i,len(devopt)+3,errmsg,CPS[GRAY])
        i += 1
        j += 1

    # connect option, select current if present
    confwin.addstr(i,1,"Connect: (_) auto (_) manual",CPS[WHITE])
    ins['auto'] = (i+zy,len("Connect: (")+zx+1,len("Connect: (")+zx+2)
    ins['manual'] = (i+zy,
                     len("Connect: (_) auto (")+zx+1,
                     len("Connect: (_) auto (")+zx+2)
    if newconf['connect']:
        confwin.addch(ins[newconf['connect']][0]-zy,
                      ins[newconf['connect']][1]-zx,
                      BON,CPS[GREEN])

    # we want two buttons Set and Cancel. Make these buttons centered. Underline
    # the first character
    btn1 = "Set"
    btn2 = "Cancel"
    btnlen = len(btn1) + len(btn2) + 1  # add a space
    btncen = (nx-btnlen) / 2            # center point for both
    # btn 1 -> underline first character
    y,x = ny-2,btncen-(len(btn1)-1)
    confwin.addstr(y,x,btn1[0],CPS[BUTTON]|curses.A_UNDERLINE)
    confwin.addstr(y,x+1,btn1[1:],CPS[BUTTON])
    ins['set'] = (y+zy,x+zx,x+zx+len(btn1)-1)
    # btn 2 -> underline first character
    y,x = ny-2,btncen+2
    confwin.addstr(y,x,btn2[0],CPS[BUTTON]|curses.A_UNDERLINE)
    confwin.addstr(y,x+1,btn2[1:],CPS[BUTTON])
    ins['cancel'] = (y+zy,x+zx,x+zx+len(btn2)-1)
    confwin.refresh()

    # capture the focus and run our execution loop
    confwin.keypad(1) # enable IOT read mouse events
    store = False
    while True:
        _ev = confwin.getch()
        if _ev == curses.KEY_MOUSE:
            # handle mouse, determine if we should check/uncheck etc
            try:
                _,mx,my,_,b = curses.getmouse()
            except curses.error:
                continue

            if b == curses.BUTTON1_CLICKED:
                # determine if we're inside a option area
                if my == ins['set'][0]:
                    if ins['set'][1] <= mx <= ins['set'][2]:
                        store = True
                        break
                    elif ins['cancel'][1] <= mx <= ins['cancel'][2]:
                        break
                elif my == ins['SSID'][0]:
                    if ins['SSID'][1] <= mx <= ins['SSID'][2]:
                        # move the cursor to the first entry char & turn on
                        curs = ins['SSID'][0],ins['SSID'][1]
                        confwin.move(curs[0]-zy,curs[1]-zx)
                        curses.curs_set(1)

                        # loop until we get <ENTER>
                        while True:
                            # get the next char
                            _ev = confwin.getch()
                            if _ev == ascii.NL or _ev == curses.KEY_ENTER: break
                            elif _ev == ascii.BS or _ev == curses.KEY_BACKSPACE:
                                if curs[1] == ins['SSID'][1]: continue
                                # delete (write over with '-') prev char, then move back
                                curs = curs[0],curs[1]-1
                                confwin.addch(curs[0]-zy,
                                               curs[1]-zx,
                                               BOFF,
                                               CPS[WHITE])
                                confwin.move(curs[0]-zy,curs[1]-zx)
                            else:
                                if curs[1] > ins['SSID'][2]:
                                    curses.flash()
                                    continue

                                # add the character, (cursor moves on its own)
                                # update our pointer for the next entry
                                try:
                                    confwin.addstr(curs[0]-zy,
                                                   curs[1]-zx,
                                                   chr(_ev),
                                                   CPS[GREEN])
                                    curs = curs[0],curs[1]+1
                                except ValueError:
                                    # put this back on and see if the outer
                                    # loop can do something with it
                                    curses.ungetch(_ev)
                                    break
                        curses.curs_set(0) # turn off the cursor
                elif my == ins['auto'][0]:
                    if ins['auto'][1] <= mx <= ins['auto'][2]:
                        if newconf['connect'] == 'manual':
                            # turn off manual
                            confwin.addch(ins['manual'][0]-zy,
                                          ins['manual'][1]-zx,
                                          BOFF,CPS[WHITE])
                        newconf['connect'] = 'auto'
                        confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])
                        confwin.refresh()
                    elif ins['manual'][1] <= mx <= ins['manual'][2]:
                        if newconf['connect'] == 'auto':
                            # turn off auto
                            confwin.addch(ins['auto'][0]-zy,
                                          ins['auto'][1]-zx,
                                          BOFF,CPS[WHITE])
                        newconf['connect'] = 'manual'
                        confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])
                        confwin.refresh()
                else:
                    # check for each listed device
                    for d in range(j):
                        if my == ins[d][0] and ins[d][1] <= mx <= ins[d][2]:
                            # check the selected dev
                            confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])

                            # determine if a previously selected needs to be unchecked
                            if newconf['dev'] is None: pass
                            elif newconf['dev'] != devs[d]:
                                i = devs.index(newconf['dev'])
                                confwin.addch(ins[i][0]-zy,
                                              ins[i][1]-zx,
                                              BOFF,
                                              CPS[WHITE])
                            newconf['dev'] = devs[d]
                            confwin.refresh()
                            break # exit the for loop
        else:
            try:
                _ch = chr(_ev).upper()
            except ValueError:
                continue
            if _ch == 'S':
                store = True
                break
            elif _ch == 'C': break
            elif _ch == 'L':
                pass

    # only 'radio buttons' are kept, check if a SSID was entered and add if so
    if store:
        ssid = confwin.instr(ins['SSID'][0]-zy,ins['SSID'][1]-zx,_SSIDLEN_)
        ssid = ssid.strip('_').strip() # remove training lines, & spaces
        if ssid: newconf['SSID'] = ssid

    # delete this window and return
    del confwin  # remove the window
    return newconf if store else None

# noinspection PyUnresolvedReferences
def view(win,nets):
    """
     displays stats on collected entities
     :param win: the main window
     :param nets: the network dict
    """
    # create new window (new window will cover the main window)
    nr,nc = win.getmaxyx()               # size of the main window
    ny,nx = 19,60                        # size of new window
    zy,zx = 1,(nc-nx)/2                  # 0,0 (top left corner) of new window
    viewwin = curses.newwin(ny,nx,zy,zx) # draw it
    viewwin.attron(CPS[GREEN])           # and add a green border
    viewwin.border(0)
    viewwin.attroff(CPS[GREEN])          # this doesn't seem to have an effect

    # inputs dict to hold the begin locations of inputs
    ins = {}  # input -> (start_y,start_x,end_x)

    # size/location variables
    ystart = 5
    apRows = 5
    staRows = 10

    # add subtitle and data title lines
    # left side (APs)
    lsub = "APs"
    lttl = "BSSID             RSS  CH  #"
    lL = len(lttl) # length of left title
    viewwin.addstr(2,(lL-len(lsub))/2+1,lsub)
    viewwin.addstr(3,1,lttl)
    viewwin.hline(4,1,curses.ACS_HLINE,lL,CPS[GREEN])
    viewwin.addch(4,lL+1,curses.ACS_UARROW,CPS[BUTTON])
    ins['aup'] = (4+zy,lL+1+zx,lL+1+zx)

    # right side (Clients)
    rx = lL+3 # length of leftsize w/ border and center elements
    rsub = "Clients"
    rttl = "STA (MAC)         RSS   S/T"
    lR = len(rttl)
    viewwin.addstr(2,(lR-len(rsub))/2+rx,rsub)
    viewwin.addstr(3,rx,rttl)
    viewwin.hline(4,rx,curses.ACS_HLINE,lR,CPS[GREEN])
    viewwin.addch(4,lR+rx,curses.ACS_UARROW,CPS[BUTTON])
    ins['sup'] = (4+zy,lR+rx+zx,lR+rx+zx)

    # add footers w/ scroll down buttons
    viewwin.hline(ystart+apRows,1,curses.ACS_HLINE,lL,CPS[GREEN])
    viewwin.addstr(ystart+apRows+1,1,"APs:")
    ins['numAPs'] = (ystart+apRows+1,len("APs:")+1,lL)
    viewwin.addstr(ystart+apRows+2,1,"Clients:")
    ins['numClts'] = (ystart+apRows+2,len("Clients:")+1,lL)
    viewwin.hline(ystart+staRows,1,curses.ACS_HLINE,lL+1,CPS[GREEN])
    viewwin.addch(ystart+apRows,lL+1,'v',CPS[BUTTON])
    ins['adown'] = (ystart+apRows+zy,lL+1+zx,lL+1+zx)
    viewwin.hline(ystart+staRows,rx,curses.ACS_HLINE,lR,CPS[GREEN])
    viewwin.addch(ystart+staRows,lR+rx,'v',CPS[BUTTON])
    ins['sdown'] = (ystart+staRows+zy,lR+rx+zx,lR+rx+zx)

    # along vertical path of scroll areas, draw a gray checkerboard
    for y in range(ystart,ystart+apRows):
        viewwin.addch(y, lL + 1, curses.ACS_CKBOARD, CPS[GRAY])
    for y in range(ystart,ystart+staRows):
        viewwin.addch(y,lR+rx,curses.ACS_CKBOARD,CPS[GRAY])

    # draw a vertical line down the center from data title to data footer
    y = None # appease pycharm
    for y in range(3,ystart+staRows):
        viewwin.addch(y,lL+2,curses.ACS_VLINE,CPS[GREEN])
    viewwin.addch(y+1,lL+2,'#',CPS[GREEN])

    # add the title and OK button. We want to center them on the subdivde where
    # APs & clients. They won't be centered then but will appear so
    title = "View"
    viewwin.addstr(1,lL,title)
    btn = "Ok"
    viewwin.addstr(ny-2,lL+1,btn[0],CPS[BUTTON]|curses.A_UNDERLINE)
    viewwin.addstr(ny-2,lL+2,btn[1:],CPS[BUTTON])
    ins['ok'] = (ny-2+zy,lL+1+zx,lL+1+zx+2)

    # create the ap pad (rows x width of lttl)
    bssids = nets.keys() # list of initial bssid keys append as new ones come in
    lsA = []             # list of initial ap lines to write
    maxA = 30            # maximum 30 bssids (should never reach)
    curA = 0             # cur index into ap list
    selA = None          # selected index into ap list
    aly,alx,ary,arx = zy+ystart,zx+1,zy+ystart+apRows-1,zx+lL
    apad = curses.newpad(maxA,lL)

    # create the clients pad (rows x width of rttl)
    lsS = []    # list of sta lines to write
    maxS = 99   # maximum 99 stas
    curS = 0    # current index into sta list
    selS = None # selected index into sta list
    sly,slx,sry,srx = zy+ystart,rx+zx,zy+ystart+staRows-1,zx+rx+lR
    spad = curses.newpad(maxS,lR)

    # fill the ap pad with any initial data (& count ttl number of clients)
    clnts = 0
    for i,bssid in enumerate(bssids):
        if i > maxA: break
        rss = nets[bssid]['rss']
        if rss is None: rss = '---'
        elif rss < -99: rss = -99
        ch = nets[bssid]['ch']
        if not ch: ch = '---'
        nC = len(nets[bssid]['stas'])
        if nc > maxS: nc = maxS
        lsA.append("{} {:>3} {:>3} {:>2}".format(bssid,rss,ch,nC))
        apad.addstr(i,0,lsA[i])

    # update the count of APs and clients
    viewwin.addstr(ins['numAPs'][0],ins['numAPs'][1]," {0}".format(len(nets)))
    viewwin.addstr(ins['numClts'][0],ins['numClts'][1]," {0}".format(clnts))

    # take the keyboard, and show this windown prior to refreshing the pads
    # Move both pads to translated coordinates IOT put them "inside"
    # the window [y,x upperleft of pad,
    #             y1,x1 upperleft of win,
    #             y2,x2 lowerright of win]
    viewwin.keypad(1)
    viewwin.refresh()
    apad.refresh(curA,0,aly,alx,ary,arx)
    spad.refresh(curS,0,sly,slx,sry,srx)

    # show and loop until ok'd
    while True:
        # check for user input
        _ev = viewwin.getch()
        if _ev == curses.KEY_MOUSE:
            try:
                _,mx,my,_,b = curses.getmouse()
                if b == curses.BUTTON1_CLICKED:
                    if aly <= my <= ary and alx <= mx <= arx: # w/in AP range
                        i = (my-aly)+curA   # index into lsA of selection
                        try:
                            # unselect any previously selected bssid & remove
                            # any clients currently shown
                            if selA is not None:
                                apad.addstr(selA,0,lsA[selA],CPS[WHITE])
                                for j,_ in enumerate(lsS):
                                    spad.addstr(j,0,' '*lR)
                                lsS = []

                            # select new (or set to none if deselecting)
                            if selA == i: selA = None
                            else:
                                selA = i
                                apad.addstr(selA,0,lsA[selA],CPS[HLITE])

                                # show this bssids clients
                                bssid = bssids[selA]
                                for j,sta in enumerate(nets[bssid]['stas']):
                                    rss = nets[bssid]['stas'][sta]['rss']
                                    if not rss: rss = '---'
                                    t = nets[bssid]['stas'][sta]['spoofed']
                                    s = nets[bssid]['stas'][sta]['success']
                                    spt = "{}/{}".format(s,t)
                                    lsS.append("{} {:>3} {:>5}".format(sta,rss,spt))
                                    spad.addstr(j,0,lsS[j])

                            # refresh the bssid & client pads
                            apad.refresh(curA,0,aly,alx,ary,arx)
                            spad.refresh(curS,0,sly,slx,sry,srx)
                        except (IndexError,KeyError):
                            continue
                    elif my == ins['ok'][0]:
                        if ins['ok'][1] <= mx <= ins['ok'][2]: break
                    elif (my,mx) == (ins['aup'][0],ins['aup'][1]):
                        if curA == 0: continue
                        curA -= 1
                        apad.refresh(curA,0,aly,alx,ary,arx)
                    elif (my,mx) == (ins['adown'][0],ins['adown'][1]):
                        if curA >= len(bssids)-apRows: continue
                        curA += 1
                        apad.refresh(curA,0,aly,alx,ary,arx)
                    elif (my,mx) == (ins['aup'][0],ins['sup'][1]): break
                    elif (my,mx) == (ins['sdown'][0],ins['sdown'][1]): break
            except curses.error:
                continue
        else:
            try:
                _ch = chr(_ev).upper()
            except ValueError:
                continue
            if _ch == 'O': break
    del viewwin
    win.touchwin()
    win.refresh()

if __name__ == '__main__':
    if os.geteuid() != 0: sys.exit("Oops. captiv8 must be run as root")
    # ui variables
    # we make state, aps and stas dicts so the update threads can see them
    err = None
    mainwin = infowin = None
    dS = {'state':_INVALID_}
    config = {'SSID':None,'dev':None,'connect': None}
    #nets = {}

    nets = {'d8:c7:c8:f3:fb:60': {'ch': None, 'stas': {}, 'rss': -75},
            'd8:c7:c8:f4:00:10': {'ch': None, 'stas': {}, 'rss': -90},
            'd8:c7:c8:f3:fa:10': {'ch': None, 'stas': {}, 'rss': -91},
            'd8:c7:c8:f3:ff:60': {'ch': None, 'stas': {}, 'rss': -86},
            'd8:c7:c8:f4:00:60': {'ch': 11, 'stas': {
                'f4:09:d8:88:ed:63': {'spoofed': 0, 'ts': 1472964477.522748,
                                      'success': 0, 'rss': -79}}, 'rss': -87},
            'd8:c7:c8:f3:ff:80': {'ch': 11, 'stas': {
                'c0:cc:f8:19:2f:17': {'spoofed': 0, 'ts': 1472964500.180947,
                                      'success': 0, 'rss': -21},
                '40:f0:2f:cb:ca:f3': {'spoofed': 0, 'ts': 1472964499.963706,
                                      'success': 0, 'rss': -68},
                'ac:b5:7d:14:54:76': {'spoofed': 0, 'ts': 1472964499.998591,
                                      'success': 0, 'rss': -74},
                'c8:ff:28:31:6a:4b': {'spoofed': 0, 'ts': 1472964455.113911,
                                      'success': 0, 'rss': -63},
                'e8:61:7e:6c:a4:e7': {'spoofed': 0, 'ts': 1472964477.567793,
                                      'success': 0, 'rss': None}}, 'rss': -37},
            'd8:c7:c8:f3:ff:b0': {'ch': 1, 'stas': {
                'c4:8e:8f:a6:79:51': {'spoofed': 0, 'ts': 1472964426.521016,
                                      'success': 0, 'rss': -83},
                'f8:cf:c5:84:71:43': {'spoofed': 0, 'ts': 1472964448.963282,
                                      'success': 0, 'rss': -91}}, 'rss': -87},
            'd8:c7:c8:f3:fc:f0': {'ch': None, 'stas': {}, 'rss': -89},
            'd8:c7:c8:f3:ff:88': {'ch': 153, 'stas': {
                '5c:c5:d4:27:42:e6': {'spoofed': 0, 'ts': 1472964379.929878,
                                      'success': 0, 'rss': -74},
                '54:4e:90:10:92:8e': {'spoofed': 0, 'ts': 1472964491.085011,
                                      'success': 0, 'rss': -78},
                '94:65:9c:73:06:ea': {'spoofed': 0, 'ts': 1472964423.827202,
                                      'success': 0, 'rss': -59},
                'd8:fc:93:8b:13:ac': {'spoofed': 0, 'ts': 1472964490.59065,
                                      'success': 0, 'rss': -77},
                'a0:cb:fd:7b:c9:4c': {'spoofed': 0, 'ts': 1472964468.864295,
                                      'success': 0, 'rss': -59}}, 'rss': -47}}

    # helpers
    c1 = c2 = None             # pipe ends for collector comms
    dq = mp.Queue()            # data queue for collect, data updater
    ublock = threading.Event() # event to block updating threads
    infoupdater = None         # the info message updater
    dataupdate = None          # the data dict updater
    collector = None           # the collector

    # catch curses, runtime and ctrl-c
    try:
        # get the windows up
        mainwin = setup()
        infowin,iwfs = infowindow(mainwin)
        mainwin.refresh()

        # create the info updater thread then the data updater thread
        infoupdater = InfoUpdateThread(infowin,ublock,dS,iwfs)
        infoupdater.start()
        dataupdater = DataUpdateThread(infowin,ublock,dq,nets,dS,iwfs)
        dataupdater.start()

        # execution loop
        while True:
            try:
                ev = mainwin.getch()
                if ev == curses.KEY_MOUSE: pass
                else:
                    ch = chr(ev).upper()
                    if ch == 'C':
                        if dS['state'] == _SCANNING_ or _CONNECTING_ <= dS['state'] < _OPERATIONAL_:
                            msgwindow(mainwin,'warn',"Cannot configure while running")
                            continue
                        newconfig = configure(mainwin,config)
                        if newconfig and cmp(newconfig,config) != 0:
                            config = newconfig
                            complete = True
                            for key in config:
                                if config[key] is None:
                                    complete = False
                                    break
                            if complete:
                                dS['state'] = _CONFIGURED_
                                updatestateinfo(infowin,iwfs,dS['state'])
                            mainmenu(mainwin,dS['state'])
                            updatesourceinfo(infowin,iwfs,config)
                            updatetargetinfo(infowin,iwfs,config)
                        mainwin.touchwin()
                        mainwin.refresh()
                    elif ch == 'R':
                        # only allow run if state is configured, or stopped
                        wwin = None
                        if dS['state'] == _CONFIGURED_ or dS['state'] == _STOPPED_:
                            # show a waitwindow while setting up collector
                            msg = "Please wait. Preparing {0}".format(config['dev'])
                            wwin = waitwindow(mainwin,"Preparing Device",msg)
                            mainwin.nodelay(True) # turn off blocking getch
                            c1,c2 = mp.Pipe()
                            try:
                                # break nets into aps and stas dict
                                aps = {}
                                stas = {}
                                for bssid in nets:
                                    aps[bssid] = nets[bssid]['rss']
                                    for sta in nets['stas']:
                                        stas[sta] = {
                                            'ASW':bssid,
                                            'ts':nets[bssid]['stas'][sta]['ts'],
                                            'rss':nets[bssid]['stas'][sta]['rss'],
                                            'rf':ch2rf(nets[bssid]['ch'])
                                        }
                                collector = collect.Collector(c2,
                                                              dq,
                                                              config['SSID'],
                                                              config['dev'],
                                                              aps,
                                                              stas)
                            except RuntimeError as e:
                                if wwin:
                                    del wwin
                                    mainwin.touchwin()
                                    mainwin.refresh()
                                    wwin = None
                                msgwindow(mainwin,'err',e.message)
                            else:
                                dS['state'] = _SCANNING_
                                collector.start()
                                mainmenu(mainwin,dS['state'])
                                del wwin
                                mainwin.touchwin()
                                mainwin.refresh()
                                ublock.set() # unblock the updaters
                        else:
                            msgwindow(mainwin,'warn',"Cannot run. Not Configured")
                    elif ch == 'S':
                        if dS['state'] >= _SCANNING_ and dS['state'] != _STOPPED_:
                            if c1: c1.send('!QUIT!')
                            while mp.active_children(): time.sleep(1)
                            ublock.clear()
                            c1.close()
                            c1 = c2 = collector = None
                            mainwin.nodelay(False)
                            dS['state'] = _STOPPED_
                            mainmenu(mainwin,dS['state'])
                            updatestateinfo(infowin,iwfs,dS['state'])
                    elif ch == 'V':
                        # only allow view if state is scanning or higher
                        #if dS['state'] < _SCANNING_:
                        #    msgwindow(mainwin,'warn',"Cannot view. Nothing to see")
                        #    continue
                        view(mainwin,nets)
                        # once we add this, we'll have to block the infoupdater
                    elif ch == 'Q':
                        if dS['state'] >= _SCANNING_ and dS['state'] != _STOPPED_:
                            if c1: c1.send('!QUIT!')
                            while mp.active_children(): time.sleep(1)
                            ublock.clear()
                            c1 = c2 = collector = None
                            mainwin.nodelay(False)
                            dS['state'] = _QUITTING_
                            mainmenu(mainwin,dS['state'])
                            updatestateinfo(infowin, iwfs, dS['state'])
                        ublock.set() # let the updaters catch _QUITTING_
                        break # get out of  the loop
            except ValueError:
                # most likely out of range errors from chr
                pass
            except error as e:
                msgwindow(mainwin,'err',e)
    except KeyboardInterrupt: pass
    except RuntimeError as e: err = e
    except curses.error as e: err = e
    finally:
        # set state to quitting and unblock if necessary
        dS['state'] = _QUITTING_
        if not ublock.is_set(): ublock.set()
        if infoupdater: infoupdater.join(5.0)
        teardown(mainwin)
        if err: sys.exit(err)
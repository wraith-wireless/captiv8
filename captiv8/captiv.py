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
import pyric
import pyric.pyw as pyw
import pyric.net.if_h as ifh
import captiv8

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
_STATE_INVALID_     = 0
_STATE_CONFIGURED_  = 1
_STATE_SCANNING_    = 2
_STATE_STOPPED_     = 3
_STATE_CONNECTING_  = 4
_STATE_CONNECTED_   = 5
_STATE_GETTINGIP_   = 6
_STATE_VERIFYING_   = 7
_STATE_OPERATIONAL_ = 8
_STATE_FLAG_NAMES_ = ['invalid','configure','scanning','stopped','connecting',
                      'connected','gettingip','verifying','operational']

# FIXED LENGTHS
_IPLEN_   = 15
_DEVLEN_  = ifh.IFNAMSIZ
_MACLEN_  = 17
_SSIDLEN_ = 32
_FIXLEN_  = 10 # arbitrary fixed field length of 10

# COLORS & COLOR PAIRS
BLACK,RED,GREEN,YELLOW,BLUE,MAGENTA,CYAN,WHITE,GRAY,BUTTON = range(10)
CPS = [None] * 10

#### INIT/DEINIT

def setup():
    """
     sets environment up and creates main window
     :returns: the main window object
    """
    # setup the console
    mmask = curses.ALL_MOUSE_EVENTS # for now accept all mouse events
    main = curses.initscr()         # get a window object
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
    win.keypad(0)
    curses.echo()
    curses.endwin()

def initcolors():
    """ initialize color pallet """
    curses.start_color()
    if not curses.has_colors():
        raise RuntimeError("Sorry. Terminal does not support colors")
    for i in range(1,9):
        curses.init_pair(i,i,BLACK)
        CPS[i] = curses.color_pair(i)
    curses.init_pair(BUTTON,WHITE,GRAY) # white on gray for buttons
    CPS[BUTTON] = curses.color_pair(BUTTON)

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
    for i,line in enumerate(_BANNER_):
        win.addstr(i+1,c,line,CPS[WHITE])

    # put the copyright in the middle
    copy = "captiv8 v{0} Copyright {1}".format(captiv8.version,captiv8.__date__)
    win.addstr(len(_BANNER_)+1,(nc-len(copy))/2,copy,CPS[BLUE])

#### WIDGETS SETUP

def mainmenu(win,state=None):
    """
     writes the main menu (caller will need to refresh)
     :param win: the main window
     :param state: current state, None = invalid
    """
    start = len(_BANNER_)+2
    win.addstr(start,3, "MENU: choose one",CPS[BLUE])
    win.addstr(start+1,5,"[C|c]onfigure",CPS[WHITE])

    # for the Run option we need to set color and text based on state
    if state == _STATE_SCANNING_:
        text = "[P|p]ause"
        color = CPS[WHITE]
    else:
        text = "[R|r]un"
        if state == _STATE_CONFIGURED_ or state == _STATE_STOPPED_:
            color = CPS[WHITE]
        else:
            color = CPS[GRAY]
    win.addstr(start+2,5,text,color)
    win.addstr(start+3,5,"[V|v]iew",CPS[WHITE])
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
    y, x = info.getmaxyx()
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
    info.addstr(4,x-25,"BSSID:",CPS[WHITE])
    info.addstr(4,x-(_MACLEN_+1),'-'*_MACLEN_,CPS[WHITE])
    info.addstr(5,1,"STA:",CPS[WHITE])
    info.addstr(5,7,'-'*_MACLEN_,CPS[WHITE])
    info.addstr(5,x-22,"IP:",CPS[WHITE])
    info.addstr(5,x-(_IPLEN_+1),'-'*_IPLEN_,CPS[WHITE])

    # add the current status at bottom left
    info.addstr(6,1,"[ ] {0}".format(_STATE_FLAG_NAMES_[_STATE_INVALID_]),CPS[WHITE])
    info.addch(6,2,ord('?'),CPS[RED])
    info.refresh()
    return info, iws

def updateinfo(win,iws,conf,state):
    """
     writes current state to info window
     :param win: the info window
     :param iws: the info window output dict should be in the form
      iws = {'dev':None,'Driver':None,'Mode':None,
           'MAC':None,'Manuf':None,'Connected':None,
           'SSID':None,'BSSID':None,
           'STA:':None,'IP':None}
     :param conf: the current config should be in the form
      config = {'SSID':None, 'dev':None, 'connect':None}
     :param state: current state
    """
    # check the conf dict for a device
    dev = conf['dev']
    if dev:
        try:
            card = pyw.getcard(dev)
            ifinfo = pyw.ifinfo(card)
            driver = ifinfo['driver'][:_FIXLEN_] # trim excess
            hwaddr = ifinfo['hwaddr'].upper()
            manuf = ifinfo['manufacturer'][:_FIXLEN_] # trim excess
            mode = pyw.modeget(card)
            conn = 'Y' if pyw.isconnected(card) else 'N'
        except pyric.error as e:
            raise RuntimeError(e)
        win.addstr(iws['dev'][0],iws['dev'][1],dev,CPS[GREEN])
        win.addstr(iws['Driver'][0],iws['Driver'][1],driver,CPS[GREEN])
        win.addstr(iws['Mode'][0],iws['Mode'][1],mode,CPS[GREEN])
        win.addstr(iws['MAC'][0],iws['MAC'][1],hwaddr,CPS[GREEN])
        win.addstr(iws['Manuf'][0],iws['Manuf'][1],manuf,CPS[GREEN])
        win.addstr(iws['Connected'][0],iws['Connected'][1],conn,CPS[GREEN])
    else:
        # have to reset: delete anything currently present
        pass

    # line 1, contains the SSID and BSSID entries
    # line 2, contains the MAC and ip entries
    #nr,nc = win.getmaxyx()
    #win.addstr(1,1,"SSID:",CPS[WHITE])
    #win.addstr(1,nc-25,"BSSID:",CPS[WHITE]) # mac is 17 chars
    #win.addstr(2,1,"MAC:",CPS[WHITE])
    #win.addstr(2,nc-22,"IP:",CPS[WHITE])

    # add empty lines
    #win.addstr(1,7,'-'*_SSIDLEN_,CPS[WHITE])
    #win.addstr(1,nc-(_MACLEN_+1),'-'*_MACLEN_,CPS[WHITE])
    #win.addstr(2,7,'-'*_MACLEN_,CPS[WHITE])
    #win.addstr(2,nc-(_IPLEN_+1),'-'*_IPLEN_,CPS[WHITE])

    #color = CPS[RED]
    #symbol = '?'
    #if state == _STATE_INVALID_: pass
    #elif state == _STATE_CONFIGURED_:
    #    color = CPS[RED]
    #    symbol = '-'
    #elif state == _STATE_OPERATIONAL_:
    #    color = CPS[GREEN]
    #    symbol = '+'
    #else:
    #    if state == _STATE_STOPPED_: color = CPS[RED]
    #    else: color = CPS[YELLOW]
    #    symbol = '/'
    #win.addstr(4,1,'[',CPS[WHITE])
    #win.addstr(4,2,symbol,color)
    #win.addstr(4,3,']',CPS[WHITE])
    #win.addstr(4,5,_STATE_FLAG_NAMES_[state].title(),CPS[WHITE])
    win.refresh()

#### MENU OPTION CALLBACKS

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
    ins = {} # input -> (start_y,start_x),length)

    # create a copy of conf to manipulate
    newconf = {}
    for key in conf: newconf[key] = conf[key]

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

    # ssid option, add if present
    confwin.addstr(2,1,"SSID: " + '_'*_SSIDLEN_,CPS[WHITE])
    ins['SSID'] = (2+zy,len("SSID: ")+zx+1,_SSIDLEN_-1)
    if newconf['SSID']:
        for i,s in enumerate(newconf['SSID']):
            confwin.addch(ins['SSID'][0]-zy,ins['SSID'][1]-zx+i,s,CPS[GREEN])

    # allow for up to 6 devices to choose in rows of 2 x 3
    confwin.addstr(3,1,"Select dev:",CPS[WHITE]) # the sub title
    i = 4 # current row
    j = 0 # current dev
    devs = pyw.winterfaces()[:8]
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
            ins[j] = (i+zy,len("n. (")+zx+2,0)
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
    ins['auto'] = (i+zy,len("Connect: (")+zx+1,0)
    ins['manual'] = (i+zy,len("Connect: (_) auto (")+zx+1,0)
    if newconf['connect']:
        confwin.addch(ins[newconf['connect']][0]-zy,ins[newconf['connect']][1]-zx,
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
    ins['set'] = (y+zy,x+zx,len(btn1)-1)
    # btn 2 -> underline first character
    y,x = ny-2,btncen+2
    confwin.addstr(y,x,btn2[0],CPS[BUTTON]|curses.A_UNDERLINE)
    confwin.addstr(y,x+1,btn2[1:],CPS[BUTTON])
    ins['cancel'] = (y+zy,x+zx,len(btn2)-1)
    confwin.refresh()

    # capture the focus and run our execution loop
    confwin.keypad(1) # enable IOT read mouse events
    store = False
    while True:
        ev = confwin.getch()
        if ev == curses.KEY_MOUSE:
            # handle mouse, determine if we should check/uncheck etc
            try:
                _,mx,my,_,b = curses.getmouse()
            except curses.error:
                continue

            if b == curses.BUTTON1_CLICKED:
                # determine if we're inside a option area
                if my == ins['set'][0]:
                    if ins['set'][1] <= mx <= ins['set'][1]+ins['set'][2]:
                        store = True
                        break
                    elif ins['cancel'][1] <= mx <= ins['cancel'][1]+ins['cancel'][2]:
                        break
                elif my == ins['SSID'][0]:
                    if ins['SSID'][1] <= mx <= ins['SSID'][1]+ins['SSID'][2]:
                        # move the cursor to the first entry char & turn on
                        curs = ins['SSID'][0],ins['SSID'][1]
                        confwin.move(curs[0]-zy,curs[1]-zx)
                        curses.curs_set(1)

                        # loop until we get <ENTER>
                        while True:
                            # get the next char
                            ev = confwin.getch()
                            if ev == ascii.NL or ev == curses.KEY_ENTER: break
                            elif ev == ascii.BS or ev == curses.KEY_BACKSPACE:
                                if curs[1] == ins['SSID'][1]: continue
                                # delete (write over with '-') prev char, then move back
                                curs = curs[0],curs[1]-1
                                confwin.addch(curs[0]-zy,
                                               curs[1]-zx,
                                               BOFF,
                                               CPS[WHITE])
                                confwin.move(curs[0]-zy,curs[1]-zx)
                            else:
                                if curs[1] > ins['SSID'][1] + ins['SSID'][2]:
                                    curses.flash()
                                    continue

                                # add the character, (cursor moves on its own)
                                # update our pointer for the next entry
                                try:
                                    confwin.addstr(curs[0]-zy,
                                                   curs[1]-zx,
                                                   chr(ev),
                                                   CPS[GREEN])
                                    curs = curs[0],curs[1]+1
                                except ValueError:
                                    # put this back on and see if the outer
                                    # loop can do something with it
                                    curses.ungetch(ev)
                                    break
                        curses.curs_set(0) # turn of the cursor
                elif my == ins['auto'][0]:
                    if ins['auto'][1] <= mx <= ins['auto'][1]+ins['auto'][2]:
                        if newconf['connect'] == 'manual':
                            # turn off manual
                            confwin.addch(ins['manual'][0]-zy,ins['manual'][1]-zx,
                                          BOFF,CPS[WHITE])
                        newconf['connect'] = 'auto'
                        confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])
                        confwin.refresh()
                    elif ins['manual'][1] <= mx <= ins['manual'][1]+ins['manual'][2]:
                        if newconf['connect'] == 'auto':
                            # turn off auto
                            confwin.addch(ins['auto'][0]-zy,ins['auto'][1]-zx,
                                          BOFF,CPS[WHITE])
                        newconf['connect'] = 'manual'
                        confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])
                        confwin.refresh()
                else:
                    # check for each listed device
                    for d in range(j):
                        if my == ins[d][0] and ins[d][1] <= mx <= ins[d][1]+ins[d][2]:
                            # check the selected dev
                            confwin.addch(my-zy,mx-zx,BON,CPS[GREEN])

                            # determine if a previously selected needs to be unchecked
                            if newconf['dev'] is None: pass
                            elif newconf['dev'] != devs[d]:
                                i = devs.index(newconf['dev'])
                                confwin.addch(ins[i][0]-zy,ins[i][1]-zx,BOFF,CPS[WHITE])
                            newconf['dev'] = devs[d]
                            confwin.refresh()
                            break # exit the for loop
        else:
            try:
                ch = chr(ev).upper()
            except ValueError:
                continue
            if ch == 'S':
                store = True
                break
            elif ch == 'C': break

    # only 'radio buttons' are kept, check if a SSID was entered and add if so
    if store:
        ssid = confwin.instr(ins['SSID'][0]-zy,ins['SSID'][1]-zx,_SSIDLEN_).strip('_')
        if ssid: newconf['SSID'] = ssid

    # delete this window and return
    del confwin  # remove the window
    return newconf if store else None

if __name__ == '__main__':
    state = _STATE_INVALID_
    mainwin = infowin = None
    err = None
    config = {'SSID': None, 'dev': None, 'connect': None}
    try:
        # get the windows up
        mainwin = setup()
        infowin,iws = infowindow(mainwin)
        mainwin.refresh()
        #updateinfo(infowin,iws,config, state)

        # execution loop
        while True:
            ev = mainwin.getch()
            if ev == curses.KEY_MOUSE: pass
            else:
                # convert the char to uppercase
                try:
                    ch = chr(ev).upper()
                except ValueError: # handle out of range errors from chr
                    continue

                # process it
                if ch == 'C':
                    newconfig = configure(mainwin,config)
                    if newconfig:
                        config = newconfig
                        updateinfo(infowin,iws,config,state)
                    mainwin.touchwin()
                    mainwin.refresh()
                elif ch == 'R': pass
                elif ch == 'V': pass
                elif ch == 'Q': break
    except KeyboardInterrupt: pass
    except RuntimeError as e: err = e
    except curses.error as e: err = e
    finally:
        teardown(mainwin)
        if err: print err
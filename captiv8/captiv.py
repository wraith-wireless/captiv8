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
import captiv8

_BANNER_ = [
"   ___     _____   _____  _______  _______  _     _   _____",
" _(___)_  (_____) (_____)(__ _ __)(_______)(_)   (_) (_____)",
"(_)   (_)(_)___(_)(_)__(_)  (_)      (_)   (_)   (_)(_)___(_)",
"(_)    _ (_______)(_____)   (_)      (_)   (_)   (_) (_____)",
"(_)___(_)(_)   (_)(_)       (_)    __(_)__  (_)_(_) (_)___(_)",
"  (___)  (_)   (_)(_)       (_)   (_______)  (___)   (_____)",
]

def setup():
    """
     sets console and main window up
     :returns: the main window object, info window object
    """
    # setup the console
    main = curses.initscr()            # get a window object
    curses.noecho()                    # turn off key echoing
    curses.cbreak()                    # turn off key buffering
    initcolors()                       # turn on and set color pallet
    main.keypad(1)                     # let curses handle multibyte special keys
    main.clear()                       # erase everything
    banner(main)                       # write the banner
    mainmenu(main)                     # then the min and menu
    main.attron(curses.color_pair(RED))  # make the border red
    main.border(0)                     # place the border
    main.attroff(curses.color_pair(RED)) # turn off the red
    info = infowindow(main)            # create the info panel/window
    curses.curs_set(0)                 # hide the cursor
    main.refresh()                     # and show everything
    return main,info

BLACK,RED,GREEN,YELLOW,BLUE,MAGENTA,CYAN,WHITE,GRAY = range(9)
def initcolors():
    """ initialize color pallet """
    curses.start_color()
    for i in range(1,9): curses.init_pair(i,i,BLACK)

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
    i = 0 # appease pycharm
    for i,line in enumerate(_BANNER_):
        win.addstr(i+1,c,line,curses.color_pair(WHITE))

    # put the copyright in the middle
    copy = "captiv8 v{0} Copyright {1}".format(captiv8.version,captiv8.__date__)
    win.addstr(i+2,(nc-len(copy))/2,copy,curses.color_pair(BLUE))

def mainmenu(win,state=None):
    """
     writes the main menu (caller will need to refresh)
     :param win: the main window
     :param state: current state, None = invalid
    """
    start = len(_BANNER_)+3
    win.addstr(start,3, "MENU: choose one",curses.color_pair(BLUE))
    win.addstr(start+1,5,"[C|c]onfigure",curses.color_pair(WHITE))
    # for the Run option we need to set color and text based on state
    text = color = None
    if state == _STATE_SCANNING_:
        text = "[P|p]ause"
        color = curses.color_pair(WHITE)
    else:
        text = "[R|r]un"
        if state == _STATE_CONFIGURED_ or state == _STATE_STOPPED_:
            color = curses.color_pair(WHITE)
        else:
            color = curses.color_pair(GRAY)
    win.addstr(start+2,5,text,color)
    win.addstr(start+3,5,"[V|v]iew",curses.color_pair(WHITE))
    win.addstr(start+4,5,"[Q|q]uit",curses.color_pair(WHITE))

def infowindow(win):
    """
     create an info window as derived window of main window win
    :param win: main window
    :returns: the info window
    """
    # try adding a subwindow for info 4 x n
    nr,nc = win.getmaxyx()
    info = win.derwin(6,nc-4,nr-7,2)
    info.attron(curses.color_pair(BLUE))
    info.border(0)
    info.attron(curses.color_pair(BLUE))
    info.refresh()
    return info

_IPLEN_  = 15
_MACLEN_ = 17
_SSIDLEN_ = 32
def updateinfo(win,state):
    """
     writes current state to info window
     :param win: the info window
     :param state: current state
    """
    # line 1, contains the SSID and BSSID entries
    # line 2, contains the MAC and ip entries
    nr,nc = win.getmaxyx()
    win.addstr(1,1,"SSID:",curses.color_pair(WHITE))
    win.addstr(1,nc-25,"BSSID:",curses.color_pair(WHITE)) # mac is 17 chars
    win.addstr(2,1,"MAC:",curses.color_pair(WHITE))
    win.addstr(2,nc-22,"IP:",curses.color_pair(WHITE))

    # add empty lines
    win.addstr(1,7,'-'*_SSIDLEN_,curses.color_pair(WHITE))
    win.addstr(1,nc-(_MACLEN_+1),'-'*_MACLEN_,curses.color_pair(WHITE))
    win.addstr(2,7,'-'*_MACLEN_,curses.color_pair(WHITE))
    win.addstr(2,nc-(_IPLEN_+1),'-'*_IPLEN_,curses.color_pair(WHITE))

    color = curses.color_pair(RED)
    symbol = '?'
    if state == _STATE_INVALID_: pass
    elif state == _STATE_CONFIGURED_:
        color = curses.color_pair(RED)
        symbol = '-'
    elif state == _STATE_OPERATIONAL_:
        color = curses.color_pair(2)
        symbol = '+'
    else:
        if state == _STATE_STOPPED_: color = curses.color_pair(RED)
        else: color = curses.color_pair(YELLOW)
        symbol = '/'
    win.addstr(4,1,'[',curses.color_pair(WHITE))
    win.addstr(4,2,symbol,color)
    win.addstr(4,3,']',curses.color_pair(WHITE))
    win.addstr(4,5,_STATE_FLAG_NAMES_[state].title(),curses.color_pair(WHITE))
    win.refresh()


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

#### STATE DEFINITIONS
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
#_STATE_FLAGS_ = {
#'invalid': (1 << _STATE_INVALID_),         # not configured
#'configured': (1 << _STATE_CONFIGURED_),   # configured but not running
#'scanning': (1 << _STATE_SCANNING_),       # scanning
#'stopped': (1 << _STATE_STOPPED_),         # not running but has been
#'connecting': (1 << _STATE_CONNECTING_),   # attempting to connect to AP
#'connected': (1 << _STATE_CONNECTED_),     # connected to AP
#'gettingip': (1 << _STATE_GETTINGIP_),     # getting ip from AP
#'verifying': (1 << _STATE_VERIFYING_),     # verifying conneciton is valid, no captive portal
#'operational': (1 << _STATE_OPERATIONAL_)  # ready to use connection
#}

#### MENU OPTION CALLBACKS

def configure(conf):
    """
     shows options to configure captiv8 for running
     :param conf: current state of configuration dict
     NOTE: configure will modify conf in-place as necessary
    """
    pass

if __name__ == '__main__':
    state = _STATE_INVALID_
    mainwin = infowin = None
    err = None
    try:
        # get the windows up
        mainwin,infowin = setup()
        updateinfo(infowin,state)

        # create our data dicts
        config = {'SSID':None,'dev':None}

        # execution loop
        ch = '!'
        while True:
            if ch == ord('!'): continue
            elif ch == ord('Q') or ch == ord('q'): break
            elif ch == ord('C') or ch == ord('c'): pass
            elif ch == ord('R') or ch == ord('r'): pass
            elif ch == ord('V') or ch == ord('v'): pass
            ch = mainwin.getch()
    except KeyboardInterrupt: pass
    except curses.error as e: err = e
    finally:
        teardown(mainwin)
        if err: print err

"""
ADDITIONAL STUFF THAT MIGHT COME IN HANDY LATER
rows, columns = window.getmaxyx()
curses.use_default_colors() # may make transparency available
0:black, 1:red, 2:green, 3:yellow, 4:blue, 5:magenta, 6:cyan, and 7:white
curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)
"""
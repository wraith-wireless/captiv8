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
    main.attron(curses.color_pair(1))  # make the border red
    main.border(0)                     # place the border
    main.attroff(curses.color_pair(1)) # turn off the red
    info = infowindow(main)            # create the info panel/window
    curses.curs_set(0)                 # hide the cursor
    main.refresh()                     # and show everything
    return main,info

def initcolors():
    """ initialize color pallet """
    curses.start_color()
    curses.init_pair(1,curses.COLOR_RED,curses.COLOR_BLACK)
    curses.init_pair(2,curses.COLOR_GREEN,curses.COLOR_BLACK)
    curses.init_pair(3,curses.COLOR_YELLOW,curses.COLOR_BLACK)
    curses.init_pair(4,curses.COLOR_BLUE,curses.COLOR_BLACK)
    curses.init_pair(5,curses.COLOR_MAGENTA,curses.COLOR_BLACK)
    curses.init_pair(6,curses.COLOR_CYAN,curses.COLOR_BLACK)
    curses.init_pair(7,curses.COLOR_WHITE,curses.COLOR_BLACK)

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
    for i,line in enumerate(_BANNER_): win.addstr(i+1,c,line,curses.color_pair(0))

    # put the copyright in the middle
    copy = "captiv8 v{0} Copyright {1}".format(captiv8.version,captiv8.__date__)
    win.addstr(i+2,(nc-len(copy))/2,copy,curses.color_pair(4))

def mainmenu(win):
    """
     writes the main menu (caller will need to refresh)
     :param win: the main window
    """
    start = len(_BANNER_)+3
    win.addstr(start,3,"MENU: choose one",curses.color_pair(4))
    win.addstr(start+1,5,"[C|c]onfigure")
    win.addstr(start+2,5,"[R|r]un")
    win.addstr(start+3,5,"[V|v]iew")
    win.addstr(start+4,5,"[Q|q]uit")

def infowindow(win):
    """
     create an info window as derived window of main window win
    :param win: main window
    :returns: the info window
    """
    # try adding a subwindow for info 4 x n
    nr,nc = win.getmaxyx()
    #info = win.derwin(5,nc-4,nr-6,2)
    info = win.derwin(6,nc-4,nr-7,2)
    info.attron(curses.color_pair(4))  # make the border blue
    info.border(0)
    info.attron(curses.color_pair(4))  # make the border blue
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
    # infowin.addstr(3,1,"STATE:",curses.color_pair(7))
    # line 1, contains the SSID and BSSID entries
    # line 2, contains the MAC and ip entries
    nr,nc = win.getmaxyx()
    win.addstr(1,1,"SSID:",curses.color_pair(0))
    win.addstr(1,nc-25,"BSSID:",curses.color_pair(0)) # mac is 17 chars
    win.addstr(2,1,"MAC:",curses.color_pair(0))
    win.addstr(2,nc-22,"IP:",curses.color_pair(0))

    # add empty lines
    win.addstr(1,7,'-'*_SSIDLEN_,curses.color_pair(0))
    win.addstr(1,nc-(_MACLEN_+1),'-'*_MACLEN_,curses.color_pair(0))
    win.addstr(2,7,'-'*_MACLEN_,curses.color_pair(0))
    win.addstr(2,nc-(_IPLEN_+1),'-'*_IPLEN_,curses.color_pair(0))

    color = curses.color_pair(1)
    symbol = '?'
    if state == _STATE_INVALID_: pass
    elif state == _STATE_CONFIGURED_:
        color = curses.color_pair(1)
        symbol = '-'
    elif state == _STATE_OPERATIONAL_:
        color = curses.color_pair(2)
        symbol = '+'
    else:
        color = curses.color_pair(1) if state == _STATE_STOPPED_ else curses.color_pair(3)
        symbol = '/'
    win.addstr(4,1,'[',curses.color_pair(0))
    win.addstr(4,2,symbol,color)
    win.addstr(4,3,']',curses.color_pair(0))
    win.addstr(4,5,_STATE_FLAG_NAMES_[state].title(),curses.color_pair(0))
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

if __name__ == '__main__':
    state = _STATE_INVALID_
    mainwin = infowin = None
    err = None
    try:
        mainwin,infowin = setup()
        updateinfo(infowin,state)

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

0:black, 1:red, 2:green, 3:yellow, 4:blue, 5:magenta, 6:cyan, and 7:white
curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)
"""
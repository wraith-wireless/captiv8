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
"            ___     _____   _____  _______  _______  _     _   _____",
"          _(___)_  (_____) (_____)(__ _ __)(_______)(_)   (_) (_____)",
"         (_)   (_)(_)___(_)(_)__(_)  (_)      (_)   (_)   (_)(_)___(_)",
"         (_)    _ (_______)(_____)   (_)      (_)   (_)   (_) (_____)",
"         (_)___(_)(_)   (_)(_)       (_)    __(_)__  (_)_(_) (_)___(_)",
"           (___)  (_)   (_)(_)       (_)   (_______)  (___)   (_____)",
"",
"                     captiv8 v{0} Copyright {1}".format(captiv8.version,
                                                         captiv8.__date__)
]

def setup():
    """
     sets console and main window up
    :returns: the main window object
    """
    # setup the console
    main = curses.initscr() # get a window object
    curses.noecho()         # turn off key echoing
    curses.cbreak()         # turn off key buffering
    main.keypad(1)          # let curses handle multibyte special keys
    main.clear()            # erase everything
    banner(main)            # write the banner
    mainmenu(main)          # then the main and menu
    main.border(0)          # place a border
    info = infowindow(main) # write the info panel/window
    curses.curs_set(0)      # hide the cursor
    main.refresh()          # and show everything
    return main,info

def banner(win):
    """
     writes the banner (caller will need to refresh)
     :param win: main window
    """
    for i, line in enumerate(_BANNER_): win.addstr(i + 1, 1, line)

def mainmenu(win):
    """
     writes the main menu (caller will need to refresh)
     :param win: the main window
    """
    win.addstr(10, 3, "MENU: choose one")
    win.addstr(11, 5, "[C|c]onfigure")
    win.addstr(12, 5, "[R|r]un")
    win.addstr(13, 5, "[M|m]etrics")
    win.addstr(14, 5, "[Q|q]uit")

def infowindow(win):
    """
     create an info window as derived window of main window win
    :param win: main window
    :returns: the info window
    """
    # try adding a subwindow for info 4 x n
    nr, nc = win.getmaxyx()
    info = win.derwin(5, nc - 4, nr - 6, 2)
    info.border(0)
    info.refresh()
    return info

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

if __name__ == '__main__':
    mainwin = infowin = None
    err = None
    try:
        mainwin, infowin = setup()

        infowin.addstr(3, 1, "STATE:")
        infowin.refresh()
        # execution loop
        ch = '!'
        while True:
            if ch == ord('Q') or ch == ord('q'): break
            ch = mainwin.getch()
    except KeyboardInterrupt: pass
    except curses.error as e: err = e
    finally:
        teardown(mainwin)
        if err: print err

"""
ADDITIONAL STUFF THAT MIGHT COME IN HANDY LATER
rows, columns = window.getmaxyx()
curses.start_color()
"""
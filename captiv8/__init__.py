#!/usr/bin/env python
""" captiv8 Captive Portal Evasion Tool

Copyright (C) 2016  Dale V. Patterson (wraith.wireless@yandex.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

Redistribution and use in source and binary forms, with or without modifications,
are permitted provided that the following conditions are met:
 o Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 o Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 o Neither the name of the orginal author Dale V. Patterson nor the names of any
   contributors may be used to endorse or promote products derived from this
   software without specific prior written permission.

Requires:
 linux (3.x or 4.x kernel)
 Python 2.7
 PyRIC >= 0.1.5
 scapy >= 2.2.0

 captiv8 0.0.1
  desc: Captiv Portal Evasion Tool
  includes: cap.py
  changes:
   See CHANGES in top-level directory

 WARNING: DO NOT import *

"""

__name__ = 'captiv8'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

# define captiv8 exceptions
#  all exceptions are tuples t=(error code,error message)
class error(EnvironmentError): pass

# for use in setup.py

# redefine version for easier access
version = __version__

# define long description
long_desc = """
captiv8 is a (Linux only) captive portal evasion tool. It enumerates all BSSIDs
that are part of a specified SSID and identifies STAs (clients) to masquerade as.
While this could be used nefariously, IOT evade paying a subscription fee, the 
primary purpose and intent is to build a tool that allows for some anonymity on
open networks and as a tool to test your captive portal or guest networks.

In short, captiv8 is an evil twin on the STA side.
"""

# CAPTIV8 0.0.1: Captive Portal Evasion

[![License: GPLv3](https://img.shields.io/pypi/l/captiv8.svg)](https://github.com/wraith-wireless/captiv8/blob/master/LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/captiv8.svg)](https://pypi.python.org/pypi/captiv8)
[![Downloads per month on PyPI](https://img.shields.io/pypi/dm/captiv8.svg)](https://pypi.python.org/pypi/captiv8)
![Supported Python Versions](https://img.shields.io/pypi/pyversions/captiv8.svg)
![Software status](https://img.shields.io/pypi/status/captiv8.svg)

## 1 DESCRIPTION:
captiv8 is a (Linux only) captive portal evasion tool. It enumerates all BSSIDs
that are part of a specified SSID and identifies STAs (clients) to masquerade as.
While this could be used nefariously, IOT evade paying a subscription fee, the 
primary purpose and intent is to build a tool that allows for some anonymity on
open networks and as a tool to test your captive portal or guest networks.

## 2. INSTALLING/USING:

### a. Requirements
captiv8 requires a Linux box preferred kernel 3.13.x and greater and Python 2.7.
It also requires the packages Scapy and PyRIC. You'll also need a wireless card 
that supports monitor mode and nl80211. And of course, an open network to test.

### b. Install from Package Manager
Obviously, the easiest way to install captiv8 is through PyPI:

    sudo pip install captiv8

ATT, captiv8 is still in POC mode and has not been packaged and uploaded to PyPI.

### c. Install from Source
Download the captiv8 tarball, untar and execute:

## 3. USING
TBD

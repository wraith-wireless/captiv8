# CAPTIV8 0.0.1: Captive Portal Evasion

            ___     _____   _____  _______  _______  _     _   _____
          _(___)_  (_____) (_____)(__ _ __)(_______)(_)   (_) (_____)
         (_)   (_)(_)___(_)(_)__(_)  (_)      (_)   (_)   (_)(_)___(_)
         (_)    _ (_______)(_____)   (_)      (_)   (_)   (_) (_____)
         (_)___(_)(_)   (_)(_)       (_)    __(_)__  (_)_(_) (_)___(_)
           (___)  (_)   (_)(_)       (_)   (_______)  (___)   (_____)

[![License: GPLv3](https://img.shields.io/pypi/l/captiv8.svg)](https://github.com/wraith-wireless/captiv8/blob/master/LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/captiv8.svg)](https://pypi.python.org/pypi/captiv8)
![Supported Python Versions](https://img.shields.io/pypi/pyversions/captiv8.svg)
![Software status](https://img.shields.io/pypi/status/captiv8.svg)

## 1 DESCRIPTION:
captiv8 is a captive portal evasion tool. It enumerates all BSSIDs that are part 
of a specified SSID (or ESSID) and identifies potential STAs (clients) to 
masquerade as. 

captiv8 can be used for a variety of reasons: 

1. You're an asshole and your surf for free off of someone else's dime whether
it's a paid subscription hotspot or a guest network in your neighborhood with 
whitelisted MACs
2. You want some anonymity. Of course you could just switch your mac address but
your traffic is tied to the same MAC. 
a. With captiv8, your traffic will blend in with someone else's
b. It's a free hotspot but requires some PII to pass the captive portal
i.e. Last name and room number
3. You're a legimate hotspot owner or guest network owner and want to test your 
network/your ability to identify illegitimate access.

## 2. INSTALLING/USING:

### a. Requirements
captiv8 requires a Linux box preferred kernel 3.13.x and greater and Python 2.7.
It also requires the packages Scapy and PyRIC. You'll also need a wireless card 
that supports monitor mode and nl80211. And of course, an open network to test.

### b. Install from Package Manager
Obviously, the easiest way to install captiv8 is through PyPI:

```bash
> sudo pip install captiv8
```

### c. Install from Source
Download the captiv8 tarball, untar to favorate directory and execute

```bash
sudo python captiv.py
```

from the captiv8/captiv8 directory.

Scapy should be present on most systems and PyRIC can be installed via pip.

## 3. USING
ATT terminal must be 80x24 before executing captiv8.

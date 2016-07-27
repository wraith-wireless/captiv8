#!/usr/bin/env python

""" setup.py: install captiv8

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

sudo pip install captiv8

"""

#__name__ = 'setup'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

from setuptools import setup, find_packages
import captiv8

setup(name='captiv8',
      version=captiv8.version,
      description="Captive Portal Evasion Tool",
      long_description=captiv8.long_desc,
      url='http://wraith-wireless.github.io/captiv8/',
      download_url="https://github.com/wraith-wireless/captiv8/archive/"+captiv8.version+".tar.gz",
      author=captiv8.__author__,
      author_email=captiv8.__email__,
      maintainer=captiv8.__maintainer__,
      maintainer_email=captiv8.__email__,
      license=captiv8.__license__,
      classifiers=['Development Status :: 4 - Beta',
                   'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                   'Intended Audience :: Developers',
                   'Intended Audience :: System Administrators',
                   'Topic :: Security',
                   'Topic :: Software Development',
                   'Topic :: Security',
                   'Topic :: System :: Networking',
                   'Topic :: Utilities',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2.7'],
    keywords='Linux Python pentest hacking wireless WLAN WiFi 802.11',
    packages=find_packages(),
    install_requires = ['PyRIC']
    # TODO: add dependencies
)

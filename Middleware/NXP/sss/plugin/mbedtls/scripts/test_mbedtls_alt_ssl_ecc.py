#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import sys
from util import *
import test_mbedtls_alt_ecc


def printUsage():
    print('Invalid input argument')
    print('Run as -  test_mbedtls_alt_ssl_ecc.py  <ec_type|all> <jrcpv2|vcom> <ip_address|port_name>  <a71ch|se050> <auth_type> <auth_key>')
    print('supported ec_type -')
    print(ecc_types)
    print('supported auth types -')
    print(auth_types)
    print('Example invocation - test_mbedtls_alt_ssl_ecc.py all jrcpv2 127.0.0.1:8050 se050 PlatformSCP key')
    sys.exit()


if len(sys.argv) < 5:
    printUsage()
else:
    if test_mbedtls_alt_ecc.doTest(sys.argv, "ssl2", __file__) != 0:
        printUsage()

#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
import subprocess
import logging
from legacy_openssl_util import *


def main():
    if len(sys.argv) >= 2:
        if sys.argv[1] != "none":
            port_data = sys.argv[1].split(':')
            JRCP_HOSTNAME = port_data[0]
            JRCP_PORT = port_data[1]

            os.environ['JRCP_HOSTNAME'] = JRCP_HOSTNAME
            os.environ['JRCP_PORT'] = JRCP_PORT
            os.environ['RJCT_SERVER_ADDR'] = sys.argv[1]

            log.info("JRCP_HOSTNAME: %s" % JRCP_HOSTNAME)
            log.info("JRCP_PORT: %s" % JRCP_PORT)
            log.info("RJCT_SERVER_ADDR: %s" % sys.argv[1])

    run("%s rand -engine %s -hex 8" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 16" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 32" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 64" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 128" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 256" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 384" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 512" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 748" % (openssl, openssl_engine))
    log.info("Program completed successfully")


def usage():
    log.info("Please provide first argument: ip_address:port of JRCP server, \"none\" for sci2c")
    log.info("Example invocation")
    log.info("  127.0.0.1:8050")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) >= 2:
        main()
    else:
        usage()


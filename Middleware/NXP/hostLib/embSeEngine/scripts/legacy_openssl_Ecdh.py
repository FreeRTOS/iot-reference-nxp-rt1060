#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
import logging
from legacy_openssl_util import *


def main():
    key_type = "prime256v1"
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

    keys_dir = os.path.join(cur_dir, '..', 'keys', key_type)

    output_dir = cur_dir + os.sep + "output"
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    KEYPAIR_REF_0 = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    KEYPAIR_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    PUBKEY_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"

    ECC_KEY_KP_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ECC_KEY_PUB_PUBONLY_A = keys_dir + os.sep + "ecc_key_pub_pubonly_A.pem"

    SHARED_SECRET_HOST_0 = output_dir + os.sep + "ecdh_host_0.bin"
    SHARED_SECRET_ENGINE_0 = output_dir + os.sep + "ecdh_engine_0.bin"
    SHARED_SECRET_HANDOVER_A = output_dir + os.sep + "ecdh_handover_A.bin"
    SHARED_SECRET_HOST_A = output_dir + os.sep + "ecdh_host_A.bin"

    log.info("## Clean up %s, %s etc." % (SHARED_SECRET_HOST_0, SHARED_SECRET_ENGINE_0))
    log.info("######################################################")
    if sys.platform.startswith("win"):
        run("del -f %s" % (SHARED_SECRET_HOST_0,))
        run("del -f %s" % (SHARED_SECRET_ENGINE_0,))
        run("del -f %s" % (SHARED_SECRET_HANDOVER_A,))
        run("del -f %s" % (SHARED_SECRET_HOST_A,))
    else:
        run("rm -f %s %s" % (SHARED_SECRET_HOST_0, SHARED_SECRET_ENGINE_0))
        run("rm -f %s %s" % (SHARED_SECRET_HANDOVER_A, SHARED_SECRET_HOST_A))

    log.info("## Do ECDH on Host (%s)" % (KEYPAIR_0,))
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, KEYPAIR_0, PUBKEY_0,
                                                                       SHARED_SECRET_HOST_0))

    log.info("## Do ECDH with Engine (%s)" % (KEYPAIR_0,))
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, KEYPAIR_REF_0, PUBKEY_0, SHARED_SECRET_ENGINE_0))

    log.info("## Confirm the two calculations are the same")
    log.info("############################################")

    log.info("#  Validate Key Handover")

    log.info("## #################################################################")
    log.info("## Validate Key Handover from Engine to OpenSSL SW implementation")
    log.info("## Do ECDH (%s) with Handover" % (ECC_KEY_KP_A))
    log.info("## #################################")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, openssl_engine, ECC_KEY_KP_A, ECC_KEY_PUB_PUBONLY_A, SHARED_SECRET_HANDOVER_A))

    log.info("## Do ECDH (%s) on Host" % (ECC_KEY_KP_A,))
    log.info("## #################################")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" %
        (openssl, ECC_KEY_KP_A, ECC_KEY_PUB_PUBONLY_A, SHARED_SECRET_HOST_A))

    log.info("## Program completed successfully")


def usage():
    log.info("Please provide as first argument: ip_address:port of JRCP server, \"none\" for sci2c")
    log.info("Example invocation")
    log.info("  127.0.0.1:8050")
    log.info("Implicitly supported key types:")
    log.info("  prime256v1 only")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) >= 2:
        main()
    else:
        usage()

#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
import subprocess
import logging
from legacy_openssl_util import *
log = logging.getLogger(__name__)


def main():
    HASH = "sha256"
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

    SIGN_KEY_REF_0 = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"
    VERIFY_KEY_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    SIGN_KEY_REF_1 = keys_dir + os.sep + "ecc_key_kp_1_ref.pem"
    VERIFY_KEY_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    SIGN_KEY_REF_2 = keys_dir + os.sep + "ecc_key_kp_2_ref.pem"
    VERIFY_KEY_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"
    SIGN_KEY_REF_3 = keys_dir + os.sep + "ecc_key_kp_3_ref.pem"
    VERIFY_KEY_3 = keys_dir + os.sep + "ecc_key_kp_3.pem"

    SIGN_KEY_0 = keys_dir + os.sep + "ecc_key_pub_0.pem"
    VERIFY_KEY_REF_0 = keys_dir + os.sep + "ecc_key_pub_0_ref.pem"
    SIGN_KEY_1 = keys_dir + os.sep + "ecc_key_pub_1.pem"
    VERIFY_KEY_REF_1 = keys_dir + os.sep + "ecc_key_pub_1_ref.pem"
    SIGN_KEY_2 = keys_dir + os.sep + "ecc_key_pub_2.pem"
    VERIFY_KEY_REF_2 = keys_dir + os.sep + "ecc_key_pub_2_ref.pem"

    ECC_KEY_KP_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ECC_KEY_KP_PUBONLY_A = keys_dir + os.sep + "ecc_key_kp_pubonly_A.pem"

    SIGNATURE_0 = output_dir + os.sep + "signature_sha256_0.bin"
    SIGNATURE_1 = output_dir + os.sep + "signature_sha256_1.bin"
    SIGNATURE_2 = output_dir + os.sep + "signature_sha256_2.bin"
    SIGNATURE_3 = output_dir + os.sep + "signature_sha256_3.bin"
    SIGNATURE_V_0 = output_dir + os.sep + "signature_v_sha256_0.bin"
    SIGNATURE_V_1 = output_dir + os.sep + "signature_v_sha256_1.bin"
    SIGNATURE_V_2 = output_dir + os.sep + "signature_v_sha256_2.bin"
    SIGNATURE_A_0 = output_dir + os.sep + "signature_a_sha256_0.bin"
    TO_SIGN = cur_dir + os.sep + "readme.md"

    log.info("###########################################################")
    log.info("Positive signing tests")

    log.info("###########################################################")
    log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_0))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -sign %s -out %s %s" %
        (openssl, openssl_engine, HASH, SIGN_KEY_REF_0, SIGNATURE_0, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with Host")
    log.info("###########################################################")
    run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_0, SIGNATURE_0, TO_SIGN))
    log.info("###########################################################")

    log.info("###########################################################")
    log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_1))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -sign %s -out %s %s" %
        (openssl, openssl_engine, HASH, SIGN_KEY_REF_1, SIGNATURE_1, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with Host")
    log.info("###########################################################")
    run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_1, SIGNATURE_1, TO_SIGN))
    log.info("###########################################################")

    log.info("###########################################################")
    log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_2))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -sign %s -out %s %s" %
        (openssl, openssl_engine, HASH, SIGN_KEY_REF_2, SIGNATURE_2, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with Host")
    log.info("###########################################################")
    run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_2, SIGNATURE_2, TO_SIGN))
    log.info("###########################################################")

    log.info("###########################################################")
    log.info("Sign the file %s with SE %s" % (TO_SIGN, SIGN_KEY_REF_3))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -sign %s -out %s %s" %
        (openssl, openssl_engine, HASH, SIGN_KEY_REF_3, SIGNATURE_3, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with Host")
    log.info("###########################################################")
    run("%s dgst -%s -prverify %s -signature %s %s" % (openssl, HASH, VERIFY_KEY_3, SIGNATURE_3, TO_SIGN))
    log.info("###########################################################")

    log.info("###########################################################")
    log.info("Positive verification tests")

    log.info("###########################################################")
    log.info("Sign the file %s with Host" % (TO_SIGN,))
    run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_0, SIGNATURE_V_0, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_0,))
    run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
        (openssl, openssl_engine, HASH, VERIFY_KEY_REF_0, SIGNATURE_V_0, TO_SIGN))

    log.info("###########################################################")
    log.info("Sign the file %s with Host" % (TO_SIGN,))
    run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_1, SIGNATURE_V_1, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_1,))
    run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
        (openssl, openssl_engine, HASH, VERIFY_KEY_REF_1, SIGNATURE_V_1, TO_SIGN))

    log.info("###########################################################")
    log.info("Sign the file %s with Host" % (TO_SIGN,))
    run("%s dgst -%s -sign %s -out %s %s" % (openssl, HASH, SIGN_KEY_2, SIGNATURE_V_2, TO_SIGN))
    log.info("###########################################################")
    log.info("Now verify the signature with SE (%s)" % (VERIFY_KEY_REF_2,))
    run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
        (openssl, openssl_engine, HASH, VERIFY_KEY_REF_2, SIGNATURE_V_2, TO_SIGN))

    log.info("###########################################################")
    log.info("Negative verification tests")
    log.info("Verify a signature with SE with a verification key (%s)" % (VERIFY_KEY_REF_0,))
    log.info("that does not match signer (%s)" % (SIGN_KEY_2,))
    log.info("###########################################################")

    ignore_result = 0
    exp_return_code = 1
    run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
        (openssl, openssl_engine, HASH, VERIFY_KEY_REF_0, SIGNATURE_V_2, TO_SIGN), ignore_result, exp_return_code)

    log.info("###########################################################")
    log.info("Validate Key Handover")
    log.info("###########################################################")
    log.info("Validate Key Handover from Engine to OpenSSL SW implementation")

    log.info("Sign the file %s with Host" % (TO_SIGN,))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -sign %s -out %s %s" %
        (openssl,  openssl_engine, HASH, ECC_KEY_KP_A, SIGNATURE_A_0, TO_SIGN,))

    log.info("Now verify the signature with SE (%s)" % (SIGNATURE_A_0, ))
    log.info("###########################################################")
    run("%s dgst -engine %s -%s -prverify %s -signature %s %s" %
        (openssl,  openssl_engine, HASH, ECC_KEY_KP_A, SIGNATURE_A_0, TO_SIGN))
    log.info("###########################################################")

    log.info("Program completed successfully")


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


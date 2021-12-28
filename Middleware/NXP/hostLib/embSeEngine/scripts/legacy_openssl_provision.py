#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#

#
# Preconditions
# -
#
# Postconditions
# - A complete set of key files (*.pem) created (existing ones overwritten)
#
#
import os
import sys
import logging
from legacy_openssl_util import *


def execute_openssl_cmd(ecc_param_pem, ecc_key_kp, ecc_key_kp_pubonly):
    cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -noout -out \"%s\"" % (openssl, ecc_param_pem, ecc_key_kp)
    run(cmd_str)
    cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, ecc_key_kp, ecc_key_kp_pubonly)
    run(cmd_str)


def main():
    key_type = "prime256v1"
    keys_dir = os.path.join(cur_dir, '..', 'keys', key_type)
    
    if not os.path.exists(keys_dir):
        os.mkdir(keys_dir)

    ecc_param_pem = keys_dir + os.sep + key_type + ".pem"

    # ECC keys to be stored in SE050/A71CH
    # ------------------------------
    ecc_key_kp_0 = keys_dir + os.sep + "ecc_key_kp_0.pem"
    ecc_key_kp_pubonly_0 = keys_dir + os.sep + "ecc_key_kp_pubonly_0.pem"
    ecc_key_kp_0_ref = keys_dir + os.sep + "ecc_key_kp_0_ref.pem"

    ecc_key_kp_1 = keys_dir + os.sep + "ecc_key_kp_1.pem"
    ecc_key_kp_pubonly_1 = keys_dir + os.sep + "ecc_key_kp_pubonly_1.pem"
    ecc_key_kp_1_ref = keys_dir + os.sep + "ecc_key_kp_1_ref.pem"

    ecc_key_kp_2 = keys_dir + os.sep + "ecc_key_kp_2.pem"
    ecc_key_kp_pubonly_2 = keys_dir + os.sep + "ecc_key_kp_pubonly_2.pem"
    ecc_key_kp_2_ref = keys_dir + os.sep + "ecc_key_kp_2_ref.pem"

    ecc_key_kp_3 = keys_dir + os.sep + "ecc_key_kp_3.pem"
    ecc_key_kp_pubonly_3 = keys_dir + os.sep + "ecc_key_kp_pubonly_3.pem"
    ecc_key_kp_3_ref = keys_dir + os.sep + "ecc_key_kp_3_ref.pem"

    ecc_key_kp_A = keys_dir + os.sep + "ecc_key_kp_A.pem"
    ecc_key_kp_pubonly_A = keys_dir + os.sep + "ecc_key_kp_pubonly_A.pem"

    ecc_key_pub_0 = keys_dir + os.sep + "ecc_key_pub_0.pem"
    ecc_key_pub_pubonly_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"
    ecc_key_pub_0_ref = keys_dir + os.sep + "ecc_key_pub_0_ref.pem"

    ecc_key_pub_1 = keys_dir + os.sep + "ecc_key_pub_1.pem"
    ecc_key_pub_pubonly_1 = keys_dir + os.sep + "ecc_key_pub_pubonly_1.pem"
    ecc_key_pub_1_ref = keys_dir + os.sep + "ecc_key_pub_1_ref.pem"

    ecc_key_pub_2 = keys_dir + os.sep + "ecc_key_pub_2.pem"
    ecc_key_pub_pubonly_2 = keys_dir + os.sep + "ecc_key_pub_pubonly_2.pem"
    ecc_key_pub_2_ref = keys_dir + os.sep + "ecc_key_pub_2_ref.pem"

    ecc_key_pub_A = keys_dir + os.sep + "ecc_key_pub_A.pem"
    ecc_key_pub_pubonly_A = keys_dir + os.sep + "ecc_key_pub_pubonly_A.pem"

    run("\"%s\" ecparam -name %s -out \"%s\"" % (openssl, key_type, ecc_param_pem,))

    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_0, ecc_key_kp_pubonly_0)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_1, ecc_key_kp_pubonly_1)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_2, ecc_key_kp_pubonly_2)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_3, ecc_key_kp_pubonly_3)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_0, ecc_key_pub_pubonly_0)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_1, ecc_key_pub_pubonly_1)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_2, ecc_key_pub_pubonly_2)
    execute_openssl_cmd(ecc_param_pem, ecc_key_kp_A, ecc_key_kp_pubonly_A)
    execute_openssl_cmd(ecc_param_pem, ecc_key_pub_A, ecc_key_pub_pubonly_A)

    subsystem = "a71ch"
    connection_method = sys.argv[1]
    connection_data = sys.argv[2]

    log.info("sys.platform = " + sys.platform)

    if os.name == 'nt':
        probeExec= os.path.join(cur_dir, '..', 'bin', 'A71CHConfigTool.exe') + ' ' + connection_data
    elif "linux" in sys.platform:
        if connection_method == 'sci2c':
            probeExec='./../bin/A71CHConfigTool'
        elif connection_method == 'jrcpv1' or connection_method == 'jrcpv2':
            probeExec='./../bin/A71CHConfigTool' + ' ' + connection_data
        else:
            log.info("  Invalid connection method: " + connection_method)
            return
    elif sys.platform == 'cygwin':
        if connection_method == 'jrcpv1' or connection_method == 'jrcpv2':
            probeExec='./../bin/A71CHConfigTool' + ' ' + connection_data
        else:
            log.info("  Invalid connection method: " + connection_method)
            return
    else:
        log.info("  Platform not supported: " + sys.platform)
        return

    run("%s debug reset" % (probeExec))

    key_id = 0
    run("%s set pair -x %x -k %s" % (probeExec, key_id, ecc_key_kp_0,))
    run("%s refpem -c 10 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_kp_0, ecc_key_kp_0_ref))

    key_id = 1
    run("%s set pair -x %x -k %s" % (probeExec, key_id, ecc_key_kp_1,))
    run("%s refpem -c 10 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_kp_1, ecc_key_kp_1_ref))

    key_id = 2
    run("%s set pair -x %x -k %s" % (probeExec, key_id, ecc_key_kp_2,))
    run("%s refpem -c 10 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_kp_2, ecc_key_kp_2_ref))

    key_id = 3
    run("%s set pair -x %x -k %s" % (probeExec, key_id, ecc_key_kp_3,))
    run("%s refpem -c 10 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_kp_3, ecc_key_kp_3_ref))

    key_id = 0
    run("%s set pub -x %x -k %s" % (probeExec, key_id, ecc_key_pub_pubonly_0,))
    run("%s refpem -c 20 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_pub_pubonly_0, ecc_key_pub_0_ref))

    key_id = 1
    run("%s set pub -x %x -k %s" % (probeExec, key_id, ecc_key_pub_pubonly_1,))
    run("%s refpem -c 20 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_pub_pubonly_1, ecc_key_pub_1_ref))

    key_id = 2
    run("%s set pub -x %x -k %s" % (probeExec, key_id, ecc_key_pub_pubonly_2,))
    run("%s refpem -c 20 -x %x -k %s -r %s" % (probeExec, key_id, ecc_key_pub_pubonly_2, ecc_key_pub_2_ref))


    log.info("Program completed successfully")


def usage():
    log.info("Please provide as first argument: connection type - sci2c, vcom, jrcpv1, jrcpv2sci2c")
    log.info("Please provide as second argument: connection parameter  - eg. COM3 , 127.0.0.1:8050, none")
    log.info("Example invocation")
    log.info("  jrcpv1 192.168.2.81:8050")
    log.info("  vcom COM3")
    log.info("  sci2c none")
    log.info("Implicitly supported key types:")
    log.info("  prime256v1 only")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) >= 3:
        main()
    else:
        usage()

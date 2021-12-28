# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

#This file is required for Android to compile A7xUtils source files.
#Android Keymaster is having dependancies on below source files.

A7X_UTILS_SRC_FILES_LIST := \
        hostlib/hostLib/libCommon/infra/sm_app_boot.c \
        hostlib/hostLib/libCommon/infra/app_boot_nfc.c \
        hostlib/hostLib/libCommon/scp/scp.c \
        hostlib/hostLib/libCommon/infra/sm_connect.c \
        hostlib/hostLib/libCommon/infra/global_platf.c

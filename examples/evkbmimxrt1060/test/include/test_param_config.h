/*
 * FreeRTOS FreeRTOS LTS Qualification Tests preview
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file test_param_config.h
 * @brief This setup the test parameters for LTS qualification test.
 */

#ifndef TEST_PARAM_CONFIG_H
#define TEST_PARAM_CONFIG_H

/**
 * @brief Configuration that indicates if the device should generate a key pair.
 *
 * @note When FORCE_GENERATE_NEW_KEY_PAIR is set to 1, the device should generate
 * a new on-device key pair and output public key. When set to 0, the device
 * should keep existing key pair.
 *
 * #define FORCE_GENERATE_NEW_KEY_PAIR   0
 */

/**
 * @brief Endpoint of the MQTT broker to connect to in mqtt test.
 *
 * #define MQTT_SERVER_ENDPOINT   "PLACE_HOLDER"
 */

/**
 * @brief Port of the MQTT broker to connect to in mqtt test.
 *
 * #define MQTT_SERVER_PORT       (8883)
 */

/**
 * @brief Endpoint of the echo server to connect to in transport interface test.
 *
 * #define ECHO_SERVER_ENDPOINT   "PLACE_HOLDER"
 */
#define ECHO_SERVER_ENDPOINT    "ec2-52-32-139-69.us-west-2.compute.amazonaws.com"

/**
 * @brief Port of the echo server to connect to in transport interface test.
 *
 * #define ECHO_SERVER_PORT       (9000)
 */
#define ECHO_SERVER_PORT        ( 9000 )

/**
 * @brief Root certificate of the echo server.
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 * #define ECHO_SERVER_ROOT_CA "PLACE_HOLDER"
 */
#define ECHO_SERVER_ROOT_CA                                              \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIICzDCCAnOgAwIBAgIUBV5JDBwC7wOuQENIeT06Rp/z6icwCgYIKoZIzj0EAwIw\n" \
    "gbsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEOMAwGA1UEBwwFUGxhY2UxFDAS\n" \
    "BgNVBAoMC1lvdXJDb21wYW55MQswCQYDVQQLDAJJVDE5MDcGA1UEAwwwZWMyLTUy\n" \
    "LTMyLTEzOS02OS51cy13ZXN0LTIuY29tcHV0ZS5hbWF6b25hd3MuY29tMTEwLwYJ\n" \
    "KoZIhvcNAQkBFiJ5b3VyRW1haWxAeW91ci1jb21wYW55LXdlYnNpdGUuY29tMB4X\n" \
    "DTIyMDIyMTE4NDQzN1oXDTIzMDIyMTE4NDQzN1owgbsxCzAJBgNVBAYTAlVTMQsw\n" \
    "CQYDVQQIDAJXQTEOMAwGA1UEBwwFUGxhY2UxFDASBgNVBAoMC1lvdXJDb21wYW55\n" \
    "MQswCQYDVQQLDAJJVDE5MDcGA1UEAwwwZWMyLTUyLTMyLTEzOS02OS51cy13ZXN0\n" \
    "LTIuY29tcHV0ZS5hbWF6b25hd3MuY29tMTEwLwYJKoZIhvcNAQkBFiJ5b3VyRW1h\n" \
    "aWxAeW91ci1jb21wYW55LXdlYnNpdGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n" \
    "AQcDQgAE5KEaznZ8ZwSaKogP1g5RemAL/RtH3mwCnHOXM6fO3zUGUOOtFmSGThJt\n" \
    "5eWR19LFaxWmaFp0/1/mQOKFIwJmuaNTMFEwHQYDVR0OBBYEFOdah57IXV6CBB1w\n" \
    "cwGYN3UZoU3IMB8GA1UdIwQYMBaAFOdah57IXV6CBB1wcwGYN3UZoU3IMA8GA1Ud\n" \
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgHpkUxi+hpZhzeyr+a8dQxW6d\n" \
    "aLndkUqx0l92Bpmqt2QCIF14OKWK5HDlFFQabUdfGTXy7fNxD9oDOlWlWgr8yO7i\n" \
    "-----END CERTIFICATE-----\n"

/**
 * @brief Client certificate to connect to echo server.
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 * #define TRANSPORT_CLIENT_CERTIFICATE NULL
 */

/**
 * @brief Client private key to connect to echo server.
 *
 * @note This is should only be used for testing purpose.
 *
 * For qualification, the key should be generated on-device.
 *
 * #define TRANSPORT_CLIENT_PRIVATE_KEY  NULL
 */

#define PKCS11_TEST_RSA_KEY_SUPPORT                     ( 0 )
#define PKCS11_TEST_EC_KEY_SUPPORT                      ( 1 )
#define PKCS11_TEST_IMPORT_PRIVATE_KEY_SUPPORT          ( 0 )
#define PKCS11_TEST_GENERATE_KEYPAIR_SUPPORT            ( 0 )
#define PKCS11_TEST_PREPROVISIONED_SUPPORT              ( 1 )
#define PKCS11_TEST_LABEL_DEVICE_PRIVATE_KEY_FOR_TLS    pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS
#define PKCS11_TEST_LABEL_DEVICE_PUBLIC_KEY_FOR_TLS     pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS
#define PKCS11_TEST_LABEL_DEVICE_CERTIFICATE_FOR_TLS    pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS


#define OTA_RSA_SHA1                                     1
#define OTA_RSA_SHA256                                   2
#define OTA_ECDSA_SHA256                                 3

/**
 * @brief Certificate type for OTA PAL test.
 * Valid options are: OTA_RSA_SHA1, OTA_RSA_SHA256, OTA_ECDSA_SHA256.
 *
 * #define OTA_PAL_TEST_CERT_TYPE OTA_ECDSA_SHA256
 */
#define OTA_PAL_TEST_CERT_TYPE                           OTA_ECDSA_SHA256

/**
 * @brief Path to cert for OTA test PAL. Used to verify signature.
 * If applicable, the device must be pre-provisioned with this certificate. Please see
 * test/common/ota/test_files for the set of certificates.
 */
#define OTA_PAL_CERTIFICATE_FILE                         "sss:00223344"

/**
 * @brief Some devices have a hard-coded name for the firmware image to boot.
 */
#define OTA_PAL_FIRMWARE_FILE                            "dummy.bin"

/**
 * @brief Some boards OTA PAL layers will use the file names passed into it for the
 * image and the certificates because their non-volatile memory is abstracted by a
 * file system. Set this to 1 if that is the case for your device.
 */
#define OTA_PAL_USE_FILE_SYSTEM                          0

/**
 * @brief 1 if using PKCS #11 to access the code sign certificate from NVM.
 */
#define OTA_PAL_READ_CERTIFICATE_FROM_NVM_WITH_PKCS11    0

#endif /* TEST_PARAM_CONFIG_H */

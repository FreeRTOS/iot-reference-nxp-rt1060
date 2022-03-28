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
#define ECHO_SERVER_ENDPOINT    "192.168.4.159"

/**
 * @brief Port of the echo server to connect to in transport interface test.
 *
 * #define ECHO_SERVER_PORT       (9000)
 */
#define ECHO_SERVER_PORT        ( 9001 )

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
    "MIIDhDCCAmwCCQDk6zBIvVIj1zANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC\n" \
    "VVMxCzAJBgNVBAgMAldBMQ4wDAYDVQQHDAVQbGFjZTEPMA0GA1UECgwGQW1hem9u\n" \
    "MQswCQYDVQQLDAJJVDEWMBQGA1UEAwwNMTkyLjE2OC40LjE1OTEhMB8GCSqGSIb3\n" \
    "DQEJARYSeW91ckVtYWlsQHlvdXIuY29tMB4XDTIyMDMxMzE4MjU1M1oXDTIzMDMx\n" \
    "MzE4MjU1M1owgYMxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEOMAwGA1UEBwwF\n" \
    "UGxhY2UxDzANBgNVBAoMBkFtYXpvbjELMAkGA1UECwwCSVQxFjAUBgNVBAMMDTE5\n" \
    "Mi4xNjguNC4xNTkxITAfBgkqhkiG9w0BCQEWEnlvdXJFbWFpbEB5b3VyLmNvbTCC\n" \
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKIF5KtA9Q0Dib9k33bDDi5G\n" \
    "lGPrQR6xr0N19c+HIrfQ8bylWHp0BUGuE+Khg87CmSPqpLehaVVYQz8SuxFO/a18\n" \
    "/IMl+I4dtfV7RSS8GHmHMPK24EAs6AwPF1yGq4d+euKlHOphPpRMZnngJrsWjtz7\n" \
    "rgYkfw3hjI6oHktPEZt002bSLCTBXUFIENPKuupb/Mh348V6WKU2eIx/Hy80WGqg\n" \
    "acUDkQW1VH4g/f7Gu3PkeeN5SN0zw3mkAr0U9Y8J5CN50TiQuaVFOQuinc2UTi+P\n" \
    "nXKMDg+4adCqpJBKuucI/ymW8Yj/eboDkgsIXfpyAf8/TwYg3b/7GR7lqcDymgEC\n" \
    "AwEAATANBgkqhkiG9w0BAQsFAAOCAQEAlznEfy73X/93MYRNsONcwdQ8ogagGj1p\n" \
    "KfafLazNyUJ46yBCEKAJd9JttUQjheGnR1XgKSPniK3l9Ep0p37vi21G6OOzcXeM\n" \
    "iutXhdcA3k6aqOVc9TGWjLbpmvtqkkFHIfa7218TONo5ESQlXI1eyxYPE3FF5Mj7\n" \
    "OAzJvsKkA+rLffL1svXL5hS59XTb9oCxk2DpJQN51XardfqDs6WMZowo2fizzp0S\n" \
    "tnYBaOPYjMTBGiGtGKsFcaSyJ0+efsFOmqJF8Vgqi+fj8nnsQmFm2QBnAy69dZqF\n" \
    "CBNYoQJfbpCFO6z56SvOHtgxkc4/IkrpV9HVZOltBrwbvHRLYSTBfQ==\n"         \
    "-----END CERTIFICATE-----"

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

#endif /* TEST_PARAM_CONFIG_H */

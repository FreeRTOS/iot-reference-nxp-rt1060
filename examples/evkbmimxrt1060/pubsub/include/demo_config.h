/*
 * FreeRTOS V202111.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

#ifndef DEMO_CONFIG_H
#define DEMO_CONFIG_H

/* FreeRTOS include. */
#include "FreeRTOS.h"

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Include logging header files and define logging macros in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define the LIBRARY_LOG_NAME and LIBRARY_LOG_LEVEL macros depending on
 * the logging configuration for DEMO.
 * 3. Include the header file "logging_stack.h", if logging is enabled for DEMO.
 */

#include "logging_levels.h"

/* Logging configuration for the Demo. */
#ifndef LIBRARY_LOG_NAME
#define LIBRARY_LOG_NAME    "MQTTDemo"
#endif

#ifndef LIBRARY_LOG_LEVEL
#define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

#include "logging.h"

/************ End of logging configuration ****************/

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique; so edit as required to ensure that no two clients connecting to
 * the same broker use the same client identifier.
 *
 *!!! Please note a #defined constant is used for convenience of demonstration
 *!!! only.  Production devices can use something unique to the device that can
 *!!! be read by software, such as a production serial number, instead of a
 *!!! hard coded constant.
 *
 * #define democonfigCLIENT_IDENTIFIER				"insert here."
 */
#define democonfigCLIENT_IDENTIFIER       "NXP_RT_1060"

/**
 * @brief Endpoint of the MQTT broker to connect to.
 *
 * This demo application can be run with any MQTT broker, that supports mutual
 * authentication.
 *
 * For AWS IoT MQTT broker, this is the Thing's REST API Endpoint.
 *
 * @note Your AWS IoT Core endpoint can be found in the AWS IoT console under
 * Settings/Custom Endpoint, or using the describe-endpoint REST API (with
 * AWS CLI command line tool).
 *
 * @note If you would like to setup an MQTT broker for running this demo,
 * please see `mqtt_broker_setup.txt`.
 *
 * #define democonfigMQTT_BROKER_ENDPOINT    "...insert here..."
 */
#define democonfigMQTT_BROKER_ENDPOINT    "192.168.1.2" //"aesqkxqeyrs5g-ats.iot.us-west-2.amazonaws.com"

/**
 * @brief The port to use for the demo.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. Using ALPN with this demo would require additional changes, including
 * setting the `pAlpnProtos` member of the `NetworkCredentials_t` struct before
 * forming the TLS connection. When using port 8883, ALPN is not required.
 *
 * #define democonfigMQTT_BROKER_PORT    ( insert here. )
 */
#define democonfigMQTT_BROKER_PORT        8883

/**
 * @brief Server's root CA certificate.
 *
 * For AWS IoT MQTT broker, this certificate is used to identify the AWS IoT
 * server and is publicly available. Refer to the AWS documentation available
 * in the link below.
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 *
 */
#define democonfigROOT_CA_PEM                                            \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" \
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" \
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n" \
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n" \
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n" \
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n" \
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n" \
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n" \
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n" \
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n" \
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n" \
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n" \
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n" \
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n" \
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n" \
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n" \
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n" \
    "rqXRfboQnoZsG4q5WTP468SQvvG5\n"                                     \
    "-----END CERTIFICATE-----\n"                                        \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\n" \
    "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n" \
    "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n" \
    "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n" \
    "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n" \
    "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\n" \
    "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n" \
    "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\n" \
    "biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\n" \
    "U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\n" \
    "aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\n" \
    "nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\n" \
    "t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\n" \
    "SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\n" \
    "BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\n" \
    "rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\n" \
    "NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\n" \
    "BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\n" \
    "BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\n" \
    "aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\n" \
    "MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\n" \
    "p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\n" \
    "5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\n" \
    "WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\n" \
    "4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\n" \
    "hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n"             \
    "-----END CERTIFICATE-----\n"

#define democonfigROOT_CA_PEM_ECC_256                                    \
    "-----BEGIN CERTIFICATE-----\n"                                      \
    "MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5\n" \
    "MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g\n" \
    "Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG\n" \
    "A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg\n" \
    "Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl\n" \
    "ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j\n" \
    "QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr\n" \
    "ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr\n" \
    "BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM\n" \
    "YyRIHN8wfdVoOw==\n"                                                 \
    "-----END CERTIFICATE-----\n"


#define democonfigCLIENT_CERT                                        \
"-----BEGIN CERTIFICATE-----\n"                                      \
"MIIDWTCCAkGgAwIBAgIUagogBlAFrSVCRmy/R4cTG0sKUY8wDQYJKoZIhvcNAQEL\n" \
"BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g\n" \
"SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTIzMDQyMDAwMDkx\n" \
"OFoXDTQ5MTIzMTIzNTk1OVowHjEcMBoGA1UEAwwTQVdTIElvVCBDZXJ0aWZpY2F0\n" \
"ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKuOqGqQQA9n2YiWWnuI\n" \
"9wh+4MOVoKvQzDROPDyMCI0RE64oNbVkJorvXT7hkfTnTHDycH+HFdW23GoF3DYM\n" \
"pC3erfZYJx8lTa8aMD54b7c/R4CKIUpul/DXHxydMsQkms2JsBrNHJe0M2Ncy7Mj\n" \
"Ls93/3X3SZH3Y3KRsHjIfKwXykAiXO8xESpMqrR17Ds1nX9YSpaV/GVwXNMW9q4Z\n" \
"OEabACB/9Abe/X8Cbx9NO9MVFUUBo4f0yDOozKLtySrZDA3pCut65d9AzL7nYFES\n" \
"7Huz3XNKJmaxkbLJAt+mOBeHvAz0sgSGXq49ZD4GQv3B+M+QfB/gdf9sCPh1Shr6\n" \
"9c8CAwEAAaNgMF4wHwYDVR0jBBgwFoAUIW/2XOdttQYIm/6ny5PMa+LkWWcwHQYD\n" \
"VR0OBBYEFIII+RWqm/Bvwcmm19dcO2Ft8i98MAwGA1UdEwEB/wQCMAAwDgYDVR0P\n" \
"AQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQA6LQZwf5aMwvW5eX2jwZ5AFXKT\n" \
"ZgeSwsCl85aa1Kd2ypkJvBFMGWzZFsBVOQ3FOkTWzSskBon37idHhTSaWHWoVlTL\n" \
"9HbGR1/hCLecyT8u9+gyQvMHFlJIBn8diyxCC1M+bRsIrlQvfDPmoAJtiYIHY5Ny\n" \
"KYACwIair5/DJuFaMpvnp2OZTtrLhmC7JDMLOX/z+2CpUNh0SpvRZKTv0TDYCjI/\n" \
"h0szC+J9CJjqkrwGo5WrPy2KKXBkpjYHM1pOOlrzan90+gBtvBwhucCM1mso2CoC\n" \
"hqPTGfFeM8Pro/YPdpnFAmOgJVp3ADV/c6PO+YoogKRtHvw2mfjY+W1cDlP3\n"     \
"-----END CERTIFICATE-----\n"


#define democonfigPRIVATE_KEY                                        \
"-----BEGIN RSA PRIVATE KEY-----\n"                                  \
"MIIEpQIBAAKCAQEAq46oapBAD2fZiJZae4j3CH7gw5Wgq9DMNE48PIwIjRETrig1\n" \
"tWQmiu9dPuGR9OdMcPJwf4cV1bbcagXcNgykLd6t9lgnHyVNrxowPnhvtz9HgIoh\n" \
"Sm6X8NcfHJ0yxCSazYmwGs0cl7QzY1zLsyMuz3f/dfdJkfdjcpGweMh8rBfKQCJc\n" \
"7zERKkyqtHXsOzWdf1hKlpX8ZXBc0xb2rhk4RpsAIH/0Bt79fwJvH0070xUVRQGj\n" \
"h/TIM6jMou3JKtkMDekK63rl30DMvudgURLse7Pdc0omZrGRsskC36Y4F4e8DPSy\n" \
"BIZerj1kPgZC/cH4z5B8H+B1/2wI+HVKGvr1zwIDAQABAoIBAQCehLbBoIBQu9iZ\n" \
"CLSaqTf5taLhlgRcPhYxzoiCObI9BqZ0qdrWvK+QeRRj4fIHpSFQy/N/IsbeLpUD\n" \
"sl6D4rJhX/zGPzYG5WUegshJMOepHuNmtjuElyP1+hBZVDdwXZJckPkUCqp80pkZ\n" \
"GsltwPij43E9Az4LjddqKYwyTq5EJEKV1XOMOuJrsrhNaQXj5nR4NAhBWCwlWlqc\n" \
"N3MF/fMnkNWxLDxszhLOqhzDGdRFG0hd2lakOrrJE0ni5nFvImaJltpVfUEaiNz6\n" \
"ApOvqnbZkc7OUkjo0AkHbKF3Rms4UK2FSdGAAClGD/pwQTexLPOcWM4/ChIWTXz0\n" \
"tqBO0xbBAoGBAOR7uysqgwI8UY2ghHQjve/zwTMpwcmLFoyO8G1Az+XTZ4cpJpPS\n" \
"ahx4JEYyVWNRNmzGd8kNByJfFlTn1jA8+UNkZ4e3sUEkqIVi1X5T1OFC1loHTm3p\n" \
"659JKdclHC4a/wUFJT5qLMcQZl9MQCT8H9r/i5J8Vl2WAa+XxuW+E8CnAoGBAMA3\n" \
"3TyvXPJoksdx/aoF3N2XmBqqf2w0gRQhx+DHF1TT8Wq4MvvBW1RmgbcqzASLnJ5X\n" \
"8EITou1CRnY3cloNH92UbiJOhilnx0YLoYrtXyjqd8gKur0oimqCa/Je1kIzVvVE\n" \
"jcLv0qUz6RxhcuL2rEJVJkyDFn56kF2p2jfmhN6ZAoGBAJfKh68GwCB1GC0B7d0G\n" \
"fcHy63BlFmQh7ioVMC809qkVyFqoAQQFrw8Y1eh4ufeQVZrwQ1YjPJEeIMTpfIdx\n" \
"ipu2EX29kJnZk8eBwJn7cZrxf1wyLG2jETEyNwTCl7UdpDyejX6opPTetVQsYRTx\n" \
"Fuy0BvKbffkQljAkojOxEohTAoGABcrpMOX8ABYkrjwCL/iDQm5KGCuhMWqXpTqr\n" \
"Ylu9mUHV2ah5aNrX3MBGEnYIte5bJu5xgBxFYa8InpFnMc2Jc00A0KnbIy5MdBDv\n" \
"qlci8gG24GFqZT7uhO0vQZuYC2Cusy+Asio2B+J7mO5a3voeENWuFMoyiFc7OIdg\n" \
"2yRoRqkCgYEAyibvs/asjQvizuq6lKareyZUjDuSm46qP3J4ZXOfikfo4hRNUg6j\n" \
"z55hEHAxmUlAYQ2Osc7Muvgu+TkSyQjzGtFq2YYaRFKxBolgvjUkfO0pittRYp9z\n" \
"SchJH+g761pKSO4maBLHZ2Y86Ok/DPVmR+/bWpawgmf52nVL8NSl66s=\n"         \
"-----END RSA PRIVATE KEY-----\n"

/**
 * @brief An option to disable Server Name Indication.
 *
 * @note When using a local Mosquitto server setup, SNI needs to be disabled
 * for an MQTT broker that only has an IP address but no hostname. However,
 * SNI should be enabled whenever possible.
 */
#define democonfigDISABLE_SNI                ( pdFALSE )

/**
 * @brief Configuration that indicates if the demo connection is made to the AWS IoT Core MQTT broker.
 *
 * If username/password based authentication is used, the demo will use appropriate TLS ALPN and
 * SNI configurations as required for the Custom Authentication feature of AWS IoT.
 * For more information, refer to the following documentation:
 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-auth.html#custom-auth-mqtt
 *
 * #define democonfigUSE_AWS_IOT_CORE_BROKER    ( 1 )
 */
#define democonfigUSE_AWS_IOT_CORE_BROKER    ( 1 )

/**
 * @brief The username value for authenticating client to the MQTT broker when
 * username/password based client authentication is used.
 *
 * For AWS IoT MQTT broker, refer to the AWS IoT documentation below for
 * details regarding client authentication with a username and password.
 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
 * An authorizer setup needs to be done, as mentioned in the above link, to use
 * username/password based client authentication.
 *
 * #define democonfigCLIENT_USERNAME    "...insert here..."
 */

/**
 * @brief The password value for authenticating client to the MQTT broker when
 * username/password based client authentication is used.
 *
 * For AWS IoT MQTT broker, refer to the AWS IoT documentation below for
 * details regarding client authentication with a username and password.
 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
 * An authorizer setup needs to be done, as mentioned in the above link, to use
 * username/password based client authentication.
 *
 * #define democonfigCLIENT_PASSWORD    "...insert here..."
 */

/**
 * @brief The name of the operating system that the application is running on.
 * The current value is given as an example. Please update for your specific
 * operating system.
 */
#define democonfigOS_NAME                   "FreeRTOS"

/**
 * @brief The version of the operating system that the application is running
 * on. The current value is given as an example. Please update for your specific
 * operating system version.
 */
#define democonfigOS_VERSION                tskKERNEL_VERSION_NUMBER

/**
 * @brief The name of the hardware platform the application is running on. The
 * current value is given as an example. Please update for your specific
 * hardware platform.
 */
#define democonfigHARDWARE_PLATFORM_NAME    "NXPRT1060"

/**
 * @brief The name of the MQTT library used and its version, following an "@"
 * symbol.
 */
#include "core_mqtt.h" /* Include coreMQTT header for MQTT_LIBRARY_VERSION macro. */
#define democonfigMQTT_LIB    "core-mqtt@"MQTT_LIBRARY_VERSION

/**
 * @brief The MQTT metrics string expected by AWS IoT.
 */
#define AWS_IOT_METRICS_STRING                                 \
    "?SDK=" democonfigOS_NAME "&Version=" democonfigOS_VERSION \
    "&Platform=" democonfigHARDWARE_PLATFORM_NAME "&MQTTLib=" democonfigMQTT_LIB

/**
 * @brief Set the stack size of the main demo task.
 *
 * In the Windows port, this stack only holds a structure. The actual
 * stack is created by an operating system thread.
 */
#define democonfigDEMO_STACKSIZE        configMINIMAL_STACK_SIZE

/**
 * @brief Set the stack size of the main demo task.
 *
 * In the Windows port, this stack only holds a structure. The actual
 * stack is created by an operating system thread.
 */
#define democonfigDEMO_TASK_PRIORITY    ( tskIDLE_PRIORITY + 1 )

#endif /* DEMO_CONFIG_H */

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
 * @file test_execution_config.h
 * @brief This setup the execution configurations for LTS qualification test.
 */

#ifndef TEST_EXECUTION_CONFIG_H
#define TEST_EXECUTION_CONFIG_H

/**
 * @brief Configuration to enable the MQTT test.
 *
 * #define MQTT_TEST_ENABLED                 (0)
 */

#define MQTT_TEST_ENABLED                 (0)

/**
 * @brief Configuration to enable the transport interface test.
 *
 * #define TRANSPORT_INTERFACE_TEST_ENABLED  (0)
 */

#define TRANSPORT_INTERFACE_TEST_ENABLED  (1)

#endif /* TEST_EXECUTION_CONFIG_H */
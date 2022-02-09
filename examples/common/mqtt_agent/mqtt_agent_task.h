/*
 * Lab-Project-coreMQTT-Agent 201215
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
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 */


#ifndef _MQTT_AGENT_TASK_H_
#define _MQTT_AGENT_TASK_H_

#include "FreeRTOS.h"
#include "task.h"


/**
 * @brief Starts the MQTT agent task.
 * MQTT agent task calls MQTTAgent_CommandLoop(), until MQTTAgent_Terminate()
 * is called. If an error occurs in the command loop, then it will reconnect the
 * TCP and MQTT connections.
 *
 * @param[in] uxStackSize Stack size for MQTT agent task.
 * @param[in] uxPriority Priority of MQTT agent task.
 */
BaseType_t xStartMQTTAgent( configSTACK_DEPTH_TYPE uxStackSize,
                            UBaseType_t uxPriority );

/**
 * @brief Function to check if the MQTT agent is running or not.
 *
 * @return pdTRUE if MQTT agent is running.
 */
BaseType_t xIsMQTTAgentRunning( void );


/**
 * @brief Function used to wait for MQTT agent to connect to broker and start running.
 *
 * @param[in] ulWaitTimeMS Wait Time in Milliseconds. Pass zero to wait indefinitely.
 * @return pdTRUE if MQTT agent is connected.
 */
BaseType_t xWaitForMQTTAgentTask( uint32_t ulWaitTimeMS );

#endif /* ifndef _MQTT_AGENT_TASK_H_ */

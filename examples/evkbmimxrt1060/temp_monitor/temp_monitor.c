/*
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
#include "FreeRTOS.h"
#include "task.h"

#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_tempmon.h"

/* MQTT library includes. */
#include "core_mqtt_agent.h"

#include "mqtt_agent_task.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Logging configuration for the demo. */

#include "logging_levels.h"

#undef LIBRARY_LOG_NAME
#define LIBRARY_LOG_NAME    "TEMP_MONITOR"

#undef LIBRARY_LOG_LEVEL
#define LIBRARY_LOG_LEVEL    LOG_DEBUG

#include "logging.h"

#define DEMO_TEMP_MONITOR             TEMPMON
#define DEMO_TEMP_LOW_HIGH_IRQn       TEMP_LOW_HIGH_IRQn
#define DEMO_TEMP_PANIC_IRQn          TEMP_PANIC_IRQn
#define DEMO_TEMP_LOW_HIGH_IRQHandler TEMP_LOW_HIGH_IRQHandler
#define DEMO_TEMP_PANIC_IRQHandler    TEMP_PANIC_IRQHandler

#define DEMO_HIGH_ALARM_TEMP 42U
#define DEMO_LOW_ALARM_TEMP  35U

#define DEMO_CLOCK_SOURCE kCLOCK_AhbClk
#define DEMO_CLOCK_DIV    kCLOCK_AhbDiv

#define DEMO_TEMP_MONITOR_JSON           \
   	"{"                                  \
        "\"value\":%0.1f,"               \
		"\"unit\":\"celsius\","          \
		"\"range\":{"                    \
        	"\"low\":%3u,"               \
			"\"high\":%3u"               \
        "},"                             \
		"\"alarm\": %1d"                 \
     "}"

#define DEMO_JSON_VALUE_LENGTH      ( 12 )

#define DEMO_TEMP_MONITOR_JSON_LENGTH    ( sizeof( DEMO_TEMP_MONITOR_JSON ) + DEMO_JSON_VALUE_LENGTH )

#define DEMO_TEMP_MONITOR_TOPIC         ( "/demo/temperature" )

#define DEMO_TEMP_MONITOR_TOPIC_LENGTH    sizeof( DEMO_TEMP_MONITOR_TOPIC )

#define DEMO_TEMP_MONITOR_TOPIC_QOS      ( MQTTQoS0 )

#define DEMO_TEMP_MONITOR_INTERVAL_MS     ( 10000 )

#define DEMO_MQTT_PUBLISH_TIMEOUT_MS      ( 50 )

/**
 * @brief Defines the structure to use as the command callback context in this
 * demo.
 */
struct MQTTAgentCommandContext
{
    MQTTStatus_t xReturnStatus;
    TaskHandle_t xTaskToNotify;
    void * pArgs;
};

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static BaseType_t prvMQTTPublish( const char * const pacTopic,
                                  uint16_t topicLen,
                                  const char * pMsg,
                                  uint32_t msgSize,
                                  uint8_t qos );

static void prvCommandCallback( MQTTAgentCommandContext_t * pCommandContext,
                                MQTTAgentReturnInfo_t * pxReturnInfo );
/*******************************************************************************
 * Variables
 ******************************************************************************/

float temperature = 0U;

volatile bool temperatureReach     = false;
uint32_t temperatureReachHighCount = 0x01U;
uint32_t temperatureReachLowCount  = 0x01U;

/**
 * @brief Static handle used for MQTT agent context.
 */
extern MQTTAgentContext_t xGlobalMqttAgentContext;

/*******************************************************************************
 * Code
 ******************************************************************************/

void DEMO_TEMP_LOW_HIGH_IRQHandler(void)
{
    temperatureReach = true;
    SDK_ISR_EXIT_BARRIER;
}


static void prvCommandCallback( MQTTAgentCommandContext_t * pCommandContext,
                                MQTTAgentReturnInfo_t * pxReturnInfo )
{
    pCommandContext->xReturnStatus = pxReturnInfo->returnCode;

    if( pCommandContext->xTaskToNotify != NULL )
    {
        xTaskNotify( pCommandContext->xTaskToNotify, ( uint32_t ) ( pxReturnInfo->returnCode ), eSetValueWithOverwrite );
    }
}



static BaseType_t prvMQTTPublish( const char * const pacTopic,
                                  uint16_t topicLen,
                                  const char * pMsg,
                                  uint32_t msgSize,
                                  uint8_t qos )
{
    BaseType_t result = pdFAIL;
    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo = { 0 };
    MQTTAgentCommandInfo_t xCommandParams = { 0 };
    MQTTAgentCommandContext_t xCommandContext = { 0 };

    publishInfo.pTopicName = pacTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    xCommandContext.xTaskToNotify = xTaskGetCurrentTaskHandle();
    xTaskNotifyStateClear( NULL );

    xCommandParams.blockTimeMs = DEMO_MQTT_PUBLISH_TIMEOUT_MS;
    xCommandParams.cmdCompleteCallback = prvCommandCallback;
    xCommandParams.pCmdCompleteCallbackContext = ( void * ) &xCommandContext;

    mqttStatus = MQTTAgent_Publish( &xGlobalMqttAgentContext,
                                    &publishInfo,
                                    &xCommandParams );

    /* Wait for command to complete so MQTTPublishInfo_t remains in scope for the
     * duration of the command. */
    if( mqttStatus == MQTTSuccess )
    {
        result = xTaskNotifyWait( 0, UINT32_MAX, NULL, pdMS_TO_TICKS( DEMO_MQTT_PUBLISH_TIMEOUT_MS ) );

        if( result == pdTRUE )
        {
            if( xCommandContext.xReturnStatus != MQTTSuccess )
            {
            	LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", xCommandContext.xReturnStatus ) );
            	result = pdFALSE;
            }
            else
            {
            	LogDebug( ( "Successfully published message to topic %.*s.", topicLen, pacTopic ) );
            }

        }
        else
        {
        	LogError( ( "Failed to receive publish acknowledgment within %u ms.", DEMO_MQTT_PUBLISH_TIMEOUT_MS ) );
        }
    }
    else
    {
    	LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );
    }

    return result;
}


/*!
 * @brief Main function
 */
void vTemperatureMonitorTask( void *pvParameters )
{
    tempmon_config_t config;
    static char temperatureJson[ DEMO_TEMP_MONITOR_JSON_LENGTH ] = { 0 };
    size_t temperatureJsonLength = 0U;

    EnableIRQ(DEMO_TEMP_LOW_HIGH_IRQn);

    LogInfo("Temperature monitor example. \r\n");

    TEMPMON_GetDefaultConfig(&config);
    config.frequency     = 0x03U;
    config.highAlarmTemp = DEMO_HIGH_ALARM_TEMP;
    config.lowAlarmTemp  = DEMO_LOW_ALARM_TEMP;

    TEMPMON_Init(DEMO_TEMP_MONITOR, &config);

    if( xIsMQTTAgentRunning() == pdFALSE )
    {
    	( void ) xWaitForMQTTAgentTask( 0U );
    }

    TEMPMON_StartMeasure(DEMO_TEMP_MONITOR);

    /* Get temperature */
    temperature = TEMPMON_GetCurrentTemperature(DEMO_TEMP_MONITOR);

    LogInfo("The chip initial temperature is %.1f degrees celsius. \r\n", temperature);

    for( ;; )
    {
        /* Get current temperature */
        temperature = TEMPMON_GetCurrentTemperature(DEMO_TEMP_MONITOR);

        LogInfo("The chip current temperature is %.1f degrees celsius. \r\n", temperature);


        temperatureJsonLength = snprintf( temperatureJson,
        		                          DEMO_TEMP_MONITOR_JSON_LENGTH,
										  DEMO_TEMP_MONITOR_JSON,
										  temperature,
										  DEMO_LOW_ALARM_TEMP,
										  DEMO_HIGH_ALARM_TEMP,
										  temperatureReach );

        if( temperatureJsonLength <= DEMO_TEMP_MONITOR_JSON_LENGTH )
        {

        	( void ) prvMQTTPublish( DEMO_TEMP_MONITOR_TOPIC,
        			                 DEMO_TEMP_MONITOR_TOPIC_LENGTH,
					                 temperatureJson,
					                 temperatureJsonLength,
					                 DEMO_TEMP_MONITOR_TOPIC_QOS );
        }

        if (temperatureReach && (temperature - DEMO_HIGH_ALARM_TEMP > 0))
        {
            temperatureReach = false;

            if (0x01U == temperatureReachHighCount)
            {
            	LogWarn("The chip temperature has reached high temperature that is %.1f degrees celsius. \r\n",
                       temperature);

                temperatureReachHighCount++;
            }
        }

        if (temperatureReach && (temperature - DEMO_LOW_ALARM_TEMP < 0))
        {
            temperatureReach = false;

            if (0x01U == temperatureReachLowCount)
            {
            	LogWarn("The chip temperature has reached low temperature that is %.1f degrees celsius. \r\n",
                       temperature);

                temperatureReachLowCount++;
            }
        }


        vTaskDelay( pdMS_TO_TICKS( DEMO_TEMP_MONITOR_INTERVAL_MS ) );
    }

    vTaskDelete( NULL );
}

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

/*
 * This file demonstrates task which use the MQTT agent API
 * to send unique MQTT payloads to unique topics over the same MQTT connection
 * to the same MQTT agent.  Some tasks use QoS0 and others QoS1.
 *
 * vSimpleSubscribePublishTask() subscribes to a topic then periodically publishes a message to the same
 * topic to which it has subscribed.  The command context sent to
 * MQTTAgent_Publish() contains a unique number that is sent back to the task
 * as a task notification from the callback function that executes when the
 * PUBLISH operation is acknowledged (or just sent in the case of QoS 0).  The
 * task checks the number it receives from the callback equals the number it
 * previously set in the command context before printing out either a success
 * or failure message.
 */


/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

/* Demo Specific configs. */
#include "demo_config.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* MQTT agent include. */
#include "core_mqtt_agent.h"

/* MQTT agent task API. */
#include "mqtt_agent_task.h"

/* Subscription manager header include. */
#include "subscription_manager.h"

/* Fetches thing name from the key store */
#include "kvstore.h"

/**
 * @brief This demo uses task notifications to signal tasks from MQTT callback
 * functions.  mqttexampleMS_TO_WAIT_FOR_NOTIFICATION defines the time, in ticks,
 * to wait for such a callback.
 */
#define mqttexampleMS_TO_WAIT_FOR_NOTIFICATION            ( 10000 )

/**
 * @brief Delay for the synchronous publisher task between publishes.
 */
#define mqttexampleDELAY_BETWEEN_PUBLISH_OPERATIONS_MS    ( 2000U )

/**
 * @brief Number of publishes done by each task in this demo.
 */
#define mqttexamplePUBLISH_COUNT                          ( 0xffffffffUL )

/**
 * @brief The maximum amount of time in milliseconds to wait for the commands
 * to be posted to the MQTT agent should the MQTT agent's command queue be full.
 * Tasks wait in the Blocked state, so don't use any CPU time.
 */
#define mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS         ( 500 )


/**
 * @brief Maximum length of the thing name as set by AWS IoT.
 * This is used to set the maximum size of topic buffer that needs to be allocated.
 */
#define mqttexampleTHING_NAME_MAX_LENGTH    ( 128 )

/**
 * @brief Size of statically allocated buffers for holding payloads.
 */
#define mqttexampleSTRING_BUFFER_LENGTH     ( 100 )

/**
 * @brief Format for the topic to which publish subscribe demo task sends messages.
 *
 * Topic Hierarchy follows the pattern: /domain_name/device_identifier/publisher_identifier.
 * domain_name identifies the domain for the metrics which is the demo name (pubsub).
 * device_identifier is string which uniquely identifies the device. We use thing name as the device identifier.
 * published_identifier identifies a unique entity within a device which is publishing the
 * message. We use FreeRTOS task number as the publisher identifier.
 *
 *
 */
#define mqttexampleTOPIC_FORMAT             "/pubsub_demo/%s/task%lu"

/**
 * @brief Size of the static buffer to hold the topic name.
 * The buffer should accommodate the topic format string, thing name and the task number which is a 32bit integer.
 */
#define mqttexampleTOPIC_BUFFER_LENGTH      ( sizeof( mqttexampleTOPIC_FORMAT ) + mqttexampleTHING_NAME_MAX_LENGTH + 10U )

/*-----------------------------------------------------------*/

/**
 * @brief Defines the structure to use as the command callback context in this
 * demo.
 */
struct MQTTAgentCommandContext
{
    MQTTStatus_t xReturnStatus;
    TaskHandle_t xTaskToNotify;
    uint32_t ulNotificationValue;
    void * pArgs;
};

/*-----------------------------------------------------------*/

/**
 * @brief Passed into MQTTAgent_Subscribe() as the callback to execute when the
 * broker ACKs the SUBSCRIBE message.  Its implementation sends a notification
 * to the task that called MQTTAgent_Subscribe() to let the task know the
 * SUBSCRIBE operation completed.  It also sets the xReturnStatus of the
 * structure passed in as the command's context to the value of the
 * xReturnStatus parameter - which enables the task to check the status of the
 * operation.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[in].xReturnStatus The result of the command.
 */
static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo );

/**
 * @brief Passed into MQTTAgent_Publish() as the callback to execute when the
 * broker ACKs the PUBLISH message.  Its implementation sends a notification
 * to the task that called MQTTAgent_Publish() to let the task know the
 * PUBLISH operation completed.  It also sets the xReturnStatus of the
 * structure passed in as the command's context to the value of the
 * xReturnStatus parameter - which enables the task to check the status of the
 * operation.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[in].xReturnStatus The result of the command.
 */
static void prvPublishCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                       MQTTAgentReturnInfo_t * pxReturnInfo );

/**
 * @brief Called by the task to wait for a notification from a callback function
 * after the task first executes either MQTTAgent_Publish()* or
 * MQTTAgent_Subscribe().
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pxCommandContext Context of the initial command.
 * @param[out] pulNotifiedValue The task's notification value after it receives
 * a notification from the callback.
 *
 * @return pdTRUE if the task received a notification, otherwise pdFALSE.
 */
static BaseType_t prvWaitForCommandAcknowledgment( uint32_t * pulNotifiedValue );

/**
 * @brief Passed into MQTTAgent_Subscribe() as the callback to execute when
 * there is an incoming publish on the topic being subscribed to.  Its
 * implementation just logs information about the incoming publish including
 * the publish messages source topic and payload.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html#example_mqtt_api_call
 *
 * @param[in] pvIncomingPublishCallbackContext Context of the initial command.
 * @param[in] pxPublishInfo Deserialized publish.
 */
static void prvIncomingPublishCallback( void * pvIncomingPublishCallbackContext,
                                        MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief Subscribe to the topic the demo task will also publish to - that
 * results in all outgoing publishes being published back to the task
 * (effectively echoed back).
 *
 * @param[in] xQoS The quality of service (QoS) to use.  Can be zero or one
 * for all MQTT brokers.  Can also be QoS2 if supported by the broker.  AWS IoT
 * does not support QoS2.
 */
static BaseType_t prvSubscribeToTopic( MQTTQoS_t xQoS,
                                       char * pcTopicFilter );


/**
 * @brief Retrieves the thing name from key store to use in demo.
 *
 * @return Pointer to null terminated string containing the thing name.
 *         NULL if thing name not found.
 */
static char * prvGetThingNameFromKeyStore( void );

/**
 * @brief The function that implements the task demonstrated by this file.
 *
 * @param pvParameters The parameters to the task.
 */
void vSimpleSubscribePublishTask( void * pvParameters );


/**
 * @brief Starts a group of publish subscribe tasks as requested by the user.
 * All tasks share the same code, task stack size and task priority, but publishes
 * messages to different topics.
 *
 * @param ulNumPubsubTasks Number of publish subscribe tasks to start.
 * @param uxStackSize Stack size for each publish subscribe task.
 * @param uxPriority Priority for each publish subscribe task.
 */
BaseType_t xStartSimplePubSubTasks( uint32_t ulNumPubsubTasks,
                                    configSTACK_DEPTH_TYPE uxStackSize,
                                    UBaseType_t uxPriority );

/*-----------------------------------------------------------*/

/**
 * @brief The MQTT agent manages the MQTT contexts.  This set the handle to the
 * context used by this demo.
 */
extern MQTTAgentContext_t xGlobalMqttAgentContext;

/*-----------------------------------------------------------*/

static void prvPublishCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                       MQTTAgentReturnInfo_t * pxReturnInfo )
{
    /* Store the result in the application defined context so the task that
     * initiated the publish can check the operation's status. */
    pxCommandContext->xReturnStatus = pxReturnInfo->returnCode;

    if( pxCommandContext->xTaskToNotify != NULL )
    {
        /* Send the context's ulNotificationValue as the notification value so
         * the receiving task can check the value it set in the context matches
         * the value it receives in the notification. */
        xTaskNotify( pxCommandContext->xTaskToNotify,
                     pxCommandContext->ulNotificationValue,
                     eSetValueWithOverwrite );
    }
}

/*-----------------------------------------------------------*/

static void prvSubscribeCommandCallback( MQTTAgentCommandContext_t * pxCommandContext,
                                         MQTTAgentReturnInfo_t * pxReturnInfo )
{
    bool xSubscriptionAdded = false;
    MQTTAgentSubscribeArgs_t * pxSubscribeArgs = ( MQTTAgentSubscribeArgs_t * ) pxCommandContext->pArgs;

    /* Store the result in the application defined context so the task that
     * initiated the subscribe can check the operation's status.  Also send the
     * status as the notification value.  These things are just done for
     * demonstration purposes. */
    pxCommandContext->xReturnStatus = pxReturnInfo->returnCode;

    /* Check if the subscribe operation is a success. Only one topic is
     * subscribed by this demo. */
    if( pxReturnInfo->returnCode == MQTTSuccess )
    {
        /* Add subscription so that incoming publishes are routed to the application
         * callback. */
        xSubscriptionAdded = SubscriptionStore_Add(
            ( SubscriptionStore_t * ) xGlobalMqttAgentContext.pIncomingCallbackContext,
            pxSubscribeArgs->pSubscribeInfo->pTopicFilter,
            pxSubscribeArgs->pSubscribeInfo->topicFilterLength,
            prvIncomingPublishCallback,
            NULL );

        if( xSubscriptionAdded == false )
        {
            LogError( ( "Failed to register an incoming publish callback for topic %.*s.",
                        pxSubscribeArgs->pSubscribeInfo->topicFilterLength,
                        pxSubscribeArgs->pSubscribeInfo->pTopicFilter ) );
        }
    }

    xTaskNotify( pxCommandContext->xTaskToNotify,
                 ( uint32_t ) ( pxReturnInfo->returnCode ),
                 eSetValueWithOverwrite );
}

/*-----------------------------------------------------------*/

static BaseType_t prvWaitForCommandAcknowledgment( uint32_t * pulNotifiedValue )
{
    BaseType_t xReturn;

    /* Wait for this task to get notified, passing out the value it gets
     * notified with. */
    xReturn = xTaskNotifyWait( 0,
                               0,
                               pulNotifiedValue,
                               pdMS_TO_TICKS( mqttexampleMS_TO_WAIT_FOR_NOTIFICATION ) );
    return xReturn;
}

/*-----------------------------------------------------------*/

static void prvIncomingPublishCallback( void * pvIncomingPublishCallbackContext,
                                        MQTTPublishInfo_t * pxPublishInfo )
{
    static char cTerminatedString[ mqttexampleSTRING_BUFFER_LENGTH ];

    ( void ) pvIncomingPublishCallbackContext;

    /* Create a message that contains the incoming MQTT payload to the logger,
     * terminating the string first. */
    if( pxPublishInfo->payloadLength < mqttexampleSTRING_BUFFER_LENGTH )
    {
        memcpy( ( void * ) cTerminatedString, pxPublishInfo->pPayload, pxPublishInfo->payloadLength );
        cTerminatedString[ pxPublishInfo->payloadLength ] = 0x00;
    }
    else
    {
        memcpy( ( void * ) cTerminatedString, pxPublishInfo->pPayload, mqttexampleSTRING_BUFFER_LENGTH );
        cTerminatedString[ mqttexampleSTRING_BUFFER_LENGTH - 1 ] = 0x00;
    }

    LogInfo( ( "Received incoming publish message %s", cTerminatedString ) );
}

/*-----------------------------------------------------------*/

static BaseType_t prvSubscribeToTopic( MQTTQoS_t xQoS,
                                       char * pcTopicFilter )
{
    MQTTStatus_t xCommandAdded;
    BaseType_t xCommandAcknowledged = pdFALSE;
    MQTTAgentSubscribeArgs_t xSubscribeArgs;
    MQTTSubscribeInfo_t xSubscribeInfo;
    static int32_t ulNextSubscribeMessageID = 0;
    MQTTAgentCommandContext_t xApplicationDefinedContext = { 0UL };
    MQTTAgentCommandInfo_t xCommandParams = { 0UL };

    /* Create a unique number of the subscribe that is about to be sent.  The number
     * is used as the command context and is sent back to this task as a notification
     * in the callback that executed upon receipt of the subscription acknowledgment.
     * That way this task can match an acknowledgment to a subscription. */
    xTaskNotifyStateClear( NULL );
    taskENTER_CRITICAL();
    {
        ulNextSubscribeMessageID++;
    }
    taskEXIT_CRITICAL();

    /* Complete the subscribe information.  The topic string must persist for
     * duration of subscription! */
    xSubscribeInfo.pTopicFilter = pcTopicFilter;
    xSubscribeInfo.topicFilterLength = ( uint16_t ) strlen( pcTopicFilter );
    xSubscribeInfo.qos = xQoS;
    xSubscribeArgs.pSubscribeInfo = &xSubscribeInfo;
    xSubscribeArgs.numSubscriptions = 1;

    /* Complete an application defined context associated with this subscribe message.
     * This gets updated in the callback function so the variable must persist until
     * the callback executes. */
    xApplicationDefinedContext.ulNotificationValue = ulNextSubscribeMessageID;
    xApplicationDefinedContext.xTaskToNotify = xTaskGetCurrentTaskHandle();
    xApplicationDefinedContext.pArgs = ( void * ) &xSubscribeArgs;

    xCommandParams.blockTimeMs = mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS;
    xCommandParams.cmdCompleteCallback = prvSubscribeCommandCallback;
    xCommandParams.pCmdCompleteCallbackContext = ( void * ) &xApplicationDefinedContext;

    /* Loop in case the queue used to communicate with the MQTT agent is full and
     * attempts to post to it time out.  The queue will not become full if the
     * priority of the MQTT agent task is higher than the priority of the task
     * calling this function. */
    LogInfo( ( "Sending subscribe request to agent for topic filter: %s with id %d",
               pcTopicFilter,
               ( int ) ulNextSubscribeMessageID ) );

    do
    {
        /* TODO: prvIncomingPublish as publish callback. */
        xCommandAdded = MQTTAgent_Subscribe( &xGlobalMqttAgentContext,
                                             &xSubscribeArgs,
                                             &xCommandParams );
    } while( xCommandAdded != MQTTSuccess );

    /* Wait for acks to the subscribe message - this is optional but done here
     * so the code below can check the notification sent by the callback matches
     * the ulNextSubscribeMessageID value set in the context above. */
    xCommandAcknowledged = prvWaitForCommandAcknowledgment( NULL );

    /* Check both ways the status was passed back just for demonstration
     * purposes. */
    if( ( xCommandAcknowledged != pdTRUE ) ||
        ( xApplicationDefinedContext.xReturnStatus != MQTTSuccess ) )
    {
        LogInfo( ( "Error or timed out waiting for ack to subscribe message topic %s",
                   pcTopicFilter ) );
    }
    else
    {
        LogInfo( ( "Received subscribe ack for topic %s containing ID %d",
                   pcTopicFilter,
                   ( int ) xApplicationDefinedContext.ulNotificationValue ) );
    }

    return xCommandAcknowledged;
}
/*-----------------------------------------------------------*/

static char * prvGetThingNameFromKeyStore( void )
{
    size_t xValueLength = 0U;
    char * pcValue = NULL;

    /* Load broker endpoint and thing name for client connection, from the key store. */
    xValueLength = KVStore_getValueLength( KVS_CORE_THING_NAME );

    if( xValueLength > 0 )
    {
        pcValue = pvPortMalloc( xValueLength + 1 );

        if( pcValue != NULL )
        {
            ( void ) KVStore_getString( KVS_CORE_THING_NAME, pcValue, ( xValueLength + 1 ) );
        }
    }

    return pcValue;
}

/*-----------------------------------------------------------*/


void vSimpleSubscribePublishTask( void * pvParameters )
{
    MQTTPublishInfo_t xPublishInfo = { 0UL };
    MQTTAgentCommandContext_t xCommandContext;
    MQTTStatus_t xCommandAdded;
    uint32_t ulTaskNumber = ( uint32_t ) pvParameters;
    MQTTQoS_t xQoS;
    TickType_t xTicksToDelay;
    MQTTAgentCommandInfo_t xCommandParams = { 0UL };
    char payloadBuf[ mqttexampleSTRING_BUFFER_LENGTH ];
    char cTopicBuf[ mqttexampleTOPIC_BUFFER_LENGTH ];
    char * pcThingName = NULL;
    uint32_t ulPublishCount = 0U, ulSuccessCount = 0U, ulFailCount = 0U;
    BaseType_t xStatus = pdPASS;
    size_t xTopicLength = 0UL;
    uint32_t ulNotification;

    /* Have different tasks use different QoS.  0 and 1.  2 can also be used
     * if supported by the broker. */
    xQoS = ( MQTTQoS_t ) ( ulTaskNumber % 2UL );

    /*
     * Get the thing name to be used in topic filter.
     */
    pcThingName = prvGetThingNameFromKeyStore();

    if( pcThingName == NULL )
    {
        xStatus = pdFAIL;
    }

    if( xStatus == pdPASS )
    {
        if( xIsMQTTAgentRunning() == pdFALSE )
        {
            xWaitForMQTTAgentTask( 0U );
        }
    }

    if( xStatus == pdPASS )
    {
        /* Create a topic name for this task to publish to. */
        xTopicLength = snprintf( cTopicBuf,
                                 mqttexampleTOPIC_BUFFER_LENGTH,
                                 mqttexampleTOPIC_FORMAT,
                                 pcThingName,
                                 ulTaskNumber );

        /*
         * Assert if the topic buffer is enough to hold the required topic.
         */
        configASSERT( xTopicLength <= mqttexampleTOPIC_BUFFER_LENGTH );

        /* Subscribe to the same topic to which this task will publish.  That will
         * result in each published message being published from the server back to
         * the target. */
        xStatus = prvSubscribeToTopic( xQoS, cTopicBuf );
    }

    if( xStatus == pdTRUE )
    {
        /* Configure the publish operation. */
        memset( ( void * ) &xPublishInfo, 0x00, sizeof( xPublishInfo ) );
        xPublishInfo.qos = xQoS;
        xPublishInfo.pTopicName = cTopicBuf;
        xPublishInfo.topicNameLength = ( uint16_t ) strlen( cTopicBuf );
        xPublishInfo.pPayload = payloadBuf;

        /* Store the handler to this task in the command context so the callback
         * that executes when the command is acknowledged can send a notification
         * back to this task. */
        memset( ( void * ) &xCommandContext, 0x00, sizeof( xCommandContext ) );
        xCommandContext.xTaskToNotify = xTaskGetCurrentTaskHandle();

        xCommandParams.blockTimeMs = mqttexampleMAX_COMMAND_SEND_BLOCK_TIME_MS;
        xCommandParams.cmdCompleteCallback = prvPublishCommandCallback;
        xCommandParams.pCmdCompleteCallbackContext = &xCommandContext;

        /* For a finite number of publishes... */
        for( ulPublishCount = 0UL; ulPublishCount < mqttexamplePUBLISH_COUNT; ulPublishCount++ )
        {
            /* Create a payload to send with the publish message.  This contains
             * the task name and an incrementing number. */
            xPublishInfo.payloadLength = snprintf( payloadBuf,
                                                   mqttexampleSTRING_BUFFER_LENGTH,
                                                   "Task %lu publishing message %d",
                                                   ulTaskNumber,
                                                   ( int ) ulPublishCount );

            /**
             * Assert if the buffer length is not enough to hold the message.
             */
            configASSERT( xPublishInfo.payloadLength <= mqttexampleSTRING_BUFFER_LENGTH );

            /* Also store the incrementing number in the command context so it can
             * be accessed by the callback that executes when the publish operation
             * is acknowledged. */
            xCommandContext.ulNotificationValue = ulPublishCount;

            LogInfo( ( "Sending publish request to agent with message \"%s\" on topic \"%s\"",
                       payloadBuf,
                       cTopicBuf ) );

            /* To ensure ulNotification doesn't accidentally hold the expected value
             * as it is to be checked against the value sent from the callback.. */
            ulNotification = ~ulPublishCount;

            xCommandAdded = MQTTAgent_Publish( &xGlobalMqttAgentContext,
                                               &xPublishInfo,
                                               &xCommandParams );
            configASSERT( xCommandAdded == MQTTSuccess );

            /* For QoS 1 and 2, wait for the publish acknowledgment.  For QoS0,
             * wait for the publish to be sent. */
            LogInfo( ( "Task %u waiting for publish %d to complete.",
                       ulTaskNumber,
                       ulPublishCount ) );
            prvWaitForCommandAcknowledgment( &ulNotification );

            /* The value received by the callback that executed when the publish was
             * acked came from the context passed into MQTTAgent_Publish() above, so
             * should match the value set in the context above. */
            if( ulNotification == ulPublishCount )
            {
                ulSuccessCount++;
                LogInfo( ( "Successfully sent QoS %u publish to topic: %s (PassCount:%d, FailCount:%d).",
                           xQoS,
                           cTopicBuf,
                           ulSuccessCount,
                           ulFailCount ) );
            }
            else
            {
                ulFailCount++;
                LogError( ( "Timed out while sending QoS %u publish to topic: %s (PassCount:%d, FailCount: %d)",
                            xQoS,
                            cTopicBuf,
                            ulSuccessCount,
                            ulFailCount ) );
            }

            /* Add a little randomness into the delay so the tasks don't remain
             * in lockstep. */
            xTicksToDelay = pdMS_TO_TICKS( mqttexampleDELAY_BETWEEN_PUBLISH_OPERATIONS_MS ) +
                            ( xTaskGetTickCount() % 0xff );
            vTaskDelay( xTicksToDelay );
        }

        /* Delete the task if it is complete. */
        LogInfo( ( "Task %u completed.", ulTaskNumber ) );
    }

    if( pcThingName != NULL )
    {
        vPortFree( pcThingName );
        pcThingName = NULL;
    }

    vTaskDelete( NULL );
}

BaseType_t xStartSimplePubSubTasks( uint32_t ulNumPubsubTasks,
                                    configSTACK_DEPTH_TYPE uxStackSize,
                                    UBaseType_t uxPriority )
{
    BaseType_t xResult = pdFAIL;
    uint32_t ulTaskNum;

    for( ulTaskNum = 0; ulTaskNum < ulNumPubsubTasks; ulTaskNum++ )
    {
        xResult = xTaskCreate( vSimpleSubscribePublishTask,
                               "PUBSUB",
                               uxStackSize,
                               ( void * ) ulTaskNum,
                               uxPriority,
                               NULL );

        if( xResult == pdFAIL )
        {
            break;
        }
    }

    return xResult;
}

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

/*
 * This demo creates multiple tasks, all of which use the MQTT agent API to
 * communicate with an MQTT broker through the same MQTT connection.
 *
 * This file contains the initial task created after the TCP/IP stack connects
 * to the network.  The task:
 *
 * 1) Connects to the MQTT broker.
 * 2) Creates the other demo tasks, in accordance with the #defines set in
 *    demo_config.h.  For example, if demo_config.h contains the following
 *    settings:
 *
 *    #define democonfigCREATE_LARGE_MESSAGE_SUB_PUB_TASK     1
 *    #define democonfigNUM_SIMPLE_SUB_PUB_TASKS_TO_CREATE 3
 *
 *    then the initial task will create the task implemented in
 *    large_message_sub_pub_demo.c and three instances of the task
 *    implemented in simple_sub_pub_demo.c.  See the comments at the top
 *    of those files for more information.
 *
 * 3) After creating the demo tasks the initial task could create the MQTT
 *    agent task.  However, as it has no other operations to perform, rather
 *    than create the MQTT agent as a separate task the initial task just calls
 *    the agent's implementing function - effectively turning itself into the
 *    MQTT agent.
 */


/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"
#include "event_groups.h"

/* Demo Specific configs. */
#include "demo_config.h"

#include "core_pkcs11_config.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* MQTT agent include. */
#include "core_mqtt_agent.h"

/* MQTT Agent ports. */
#include "freertos_agent_message.h"
#include "freertos_command_pool.h"

/* Exponential backoff retry include. */
#include "backoff_algorithm.h"

/* Subscription manager header include. */
#include "subscription_manager.h"

#include "using_mbedtls.h"

#include "kvStore.h"

/**
 * @brief Dimensions the buffer used to serialize and deserialize MQTT packets.
 * @note Specified in bytes.  Must be large enough to hold the maximum
 * anticipated MQTT payload.
 */
#ifndef MQTT_AGENT_NETWORK_BUFFER_SIZE
    #define MQTT_AGENT_NETWORK_BUFFER_SIZE    ( 5000 )
#endif

/**
 * These configuration settings are required to run the demo.
 */

/**
 * @brief Timeout for receiving CONNACK after sending an MQTT CONNECT packet.
 * Defined in milliseconds.
 */
#define mqttexampleCONNACK_RECV_TIMEOUT_MS           ( 2000U )

/**
 * @brief The maximum number of retries for network operation with server.
 */
#define RETRY_MAX_ATTEMPTS                           ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying failed operation
 *  with server.
 */
#define RETRY_MAX_BACKOFF_DELAY_MS                   ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for network operation retry
 * attempts.
 */
#define RETRY_BACKOFF_BASE_MS                        ( 500U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 *  between two Control Packets.
 *
 *  It is the responsibility of the Client to ensure that the interval between
 *  Control Packets being sent does not exceed the this Keep Alive value. In the
 *  absence of sending any other Control Packets, the Client MUST send a
 *  PINGREQ Packet.
 *//*_RB_ Move to be the responsibility of the agent. */
#define mqttexampleKEEP_ALIVE_INTERVAL_SECONDS       ( 60U )

/**
 * @brief Socket send and receive timeouts to use.  Specified in milliseconds.
 */
#define mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS    ( 750 )

/**
 * @brief Used to convert times to/from ticks and milliseconds.
 */
#define mqttexampleMILLISECONDS_PER_SECOND           ( 1000U )
#define mqttexampleMILLISECONDS_PER_TICK             ( mqttexampleMILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

/**
 * @brief The MQTT agent manages the MQTT contexts.  This set the handle to the
 * context used by this demo.
 */
#define mqttexampleMQTT_CONTEXT_HANDLE               ( ( MQTTContextHandle_t ) 0 )


/**
 * @brief Event bit used to indicated that MQTT agent has started running.
 */
#define MQTT_AGENT_STARTED_EVENT_BIT                ( 1U << 0 )

/*-----------------------------------------------------------*/

/**
 * @brief Initializes an MQTT context, including transport interface and
 * network buffer.
 *
 * @return `MQTTSuccess` if the initialization succeeds, else `MQTTBadParameter`.
 */
static MQTTStatus_t prvMQTTInit( void );

/**
 * @brief Sends an MQTT Connect packet over the already connected TCP socket.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] xCleanSession If a clean session should be established.
 *
 * @return `MQTTSuccess` if connection succeeds, else appropriate error code
 * from MQTT_Connect.
 */
static MQTTStatus_t prvMQTTConnect( bool xCleanSession );

/**
 * @brief Connect a TCP socket to the MQTT broker.
 *
 * @param[in] pxNetworkContext Network context.
 *
 * @return `pdPASS` if connection succeeds, else `pdFAIL`.
 */
static BaseType_t prvSocketConnect( NetworkContext_t * pxNetworkContext );

/**
 * @brief Disconnect a TCP connection.
 *
 * @param[in] pxNetworkContext Network context.
 *
 * @return `pdPASS` if disconnect succeeds, else `pdFAIL`.
 */
static BaseType_t prvSocketDisconnect( NetworkContext_t * pxNetworkContext );


/**
 * @brief Fan out the incoming publishes to the callbacks registered by different
 * tasks. If there are no callbacks registered for the incoming publish, it will be
 * passed to the unsolicited publish handler.
 *
 * @param[in] pMqttAgentContext Agent context.
 * @param[in] packetId Packet ID of publish.
 * @param[in] pxPublishInfo Info of incoming publish.
 */
static void prvIncomingPublishCallback( MQTTAgentContext_t * pMqttAgentContext,
                                        uint16_t packetId,
                                        MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief The timer query function provided to the MQTT context.
 *
 * @return Time in milliseconds.
 */
static uint32_t prvGetTimeMs( void );

/**
 * @brief Connects a TCP socket to the MQTT broker, then creates and MQTT
 * connection to the same.
 */
static BaseType_t prvConnectToMQTTBroker( bool xIsReconnect );



static void prvMQTTAgentTask( void * pvParameters );
/*-----------------------------------------------------------*/

/**
 * @brief The network context used by the MQTT library transport interface.
 * See https://www.freertos.org/network-interface.html
 */
static NetworkContext_t xNetworkContext;

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

MQTTAgentContext_t xGlobalMqttAgentContext;

static uint8_t xNetworkBuffer[ MQTT_AGENT_NETWORK_BUFFER_SIZE ];

static MQTTAgentMessageContext_t xCommandQueue;

/**
 * @brief ThingName which is used as the client identifier for MQTT connection.
 * Thing name is retrieved  at runtime from a key value store.
 */
static char *pcThingName = NULL;
static size_t xThingNameLength = 0U;

/**
 * @brief Broker endpoint name for the MQTT connection.
 * Broker endpoint name is retrieved at runtime from a key value store.
 */
static char *pcBrokerEndpoint = NULL;
static size_t xBrokerEndpointLength = 0U;

/**
 * @brief Broker port used for the MQTT connection.
 * Broker port is retrieved at runtime from a key value store.
 */
static uint32_t ulBrokerPort;

/**
 * @brief Event group used by other tasks to synchronize with the MQTT agent.
 */
static EventGroupHandle_t xMQTTAgentEventGrp;

/*-----------------------------------------------------------*/

static MQTTStatus_t prvMQTTInit( void )
{
    TransportInterface_t xTransport;
    MQTTStatus_t xReturn;
    MQTTFixedBuffer_t xFixedBuffer = { .pBuffer = xNetworkBuffer, .size = MQTT_AGENT_NETWORK_BUFFER_SIZE };
    static uint8_t staticQueueStorageArea[ MQTT_AGENT_COMMAND_QUEUE_LENGTH * sizeof( MQTTAgentCommand_t * ) ];
    static StaticQueue_t staticQueueStructure;
    MQTTAgentMessageInterface_t messageInterface =
    {
        .pMsgCtx        = NULL,
        .send           = Agent_MessageSend,
        .recv           = Agent_MessageReceive,
        .getCommand     = Agent_GetCommand,
        .releaseCommand = Agent_ReleaseCommand
    };
    SubscriptionStore_t * pxSubscriptionStore = NULL;


    pxSubscriptionStore = SubscriptionStore_Create();
    configASSERT( pxSubscriptionStore != NULL );

    LogDebug( ( "Creating command queue." ) );
    xCommandQueue.queue = xQueueCreateStatic( MQTT_AGENT_COMMAND_QUEUE_LENGTH,
                                              sizeof( MQTTAgentCommand_t * ),
                                              staticQueueStorageArea,
                                              &staticQueueStructure );
    configASSERT( xCommandQueue.queue );
    messageInterface.pMsgCtx = &xCommandQueue;

    /* Initialize the task pool. */
    Agent_InitializePool();

    /* Fill in Transport Interface send and receive function pointers. */
    xTransport.pNetworkContext = &xNetworkContext;
    xTransport.send = TLS_FreeRTOS_send;
    xTransport.recv = TLS_FreeRTOS_recv;

    /* Initialize MQTT library. */
    xReturn = MQTTAgent_Init( &xGlobalMqttAgentContext,
                              &messageInterface,
                              &xFixedBuffer,
                              &xTransport,
                              prvGetTimeMs,
                              prvIncomingPublishCallback,
                              /* Context to pass into the callback. Passing the pointer to subscription array. */
							  pxSubscriptionStore );

    return xReturn;
}

/*-----------------------------------------------------------*/

static MQTTStatus_t prvMQTTConnect( bool xCleanSession )
{
    MQTTStatus_t xResult;
    MQTTConnectInfo_t xConnectInfo;
    bool xSessionPresent = false;

    /* Many fields are not used in this demo so start with everything at 0. */
    memset( &xConnectInfo, 0x00, sizeof( xConnectInfo ) );

    /* Start with a clean session i.e. direct the MQTT broker to discard any
     * previous session data. Also, establishing a connection with clean session
     * will ensure that the broker does not store any data when this client
     * gets disconnected. */
    xConnectInfo.cleanSession = xCleanSession;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    xConnectInfo.pClientIdentifier = pcThingName;
    xConnectInfo.clientIdentifierLength = ( uint16_t ) xThingNameLength;

    /* Set MQTT keep-alive period. It is the responsibility of the application
     * to ensure that the interval between Control Packets being sent does not
     * exceed the Keep Alive value. In the absence of sending any other Control
     * Packets, the Client MUST send a PINGREQ Packet.  This responsibility will
     * be moved inside the agent. */
    xConnectInfo.keepAliveSeconds = mqttexampleKEEP_ALIVE_INTERVAL_SECONDS;

    /* Append metrics when connecting to the AWS IoT Core broker. */
    #ifdef democonfigUSE_AWS_IOT_CORE_BROKER
        #ifdef democonfigCLIENT_USERNAME
            xConnectInfo.pUserName = CLIENT_USERNAME_WITH_METRICS;
            xConnectInfo.userNameLength = ( uint16_t ) strlen( CLIENT_USERNAME_WITH_METRICS );
            xConnectInfo.pPassword = democonfigCLIENT_PASSWORD;
            xConnectInfo.passwordLength = ( uint16_t ) strlen( democonfigCLIENT_PASSWORD );
        #else
            xConnectInfo.pUserName = AWS_IOT_METRICS_STRING;
            xConnectInfo.userNameLength = AWS_IOT_METRICS_STRING_LENGTH;
            /* Password for authentication is not used. */
            xConnectInfo.pPassword = NULL;
            xConnectInfo.passwordLength = 0U;
        #endif
    #else /* ifdef democonfigUSE_AWS_IOT_CORE_BROKER */
        #ifdef democonfigCLIENT_USERNAME
            xConnectInfo.pUserName = democonfigCLIENT_USERNAME;
            xConnectInfo.userNameLength = ( uint16_t ) strlen( democonfigCLIENT_USERNAME );
            xConnectInfo.pPassword = democonfigCLIENT_PASSWORD;
            xConnectInfo.passwordLength = ( uint16_t ) strlen( democonfigCLIENT_PASSWORD );
        #endif /* ifdef democonfigCLIENT_USERNAME */
    #endif /* ifdef democonfigUSE_AWS_IOT_CORE_BROKER */

    LogInfo( ( "Creating an MQTT connection to the broker." ) );

    /* Send MQTT CONNECT packet to broker. MQTT's Last Will and Testament feature
     * is not used in this demo, so it is passed as NULL. */
    xResult = MQTT_Connect( &( xGlobalMqttAgentContext.mqttContext ),
                            &xConnectInfo,
                            NULL,
                            mqttexampleCONNACK_RECV_TIMEOUT_MS,
                            &xSessionPresent );
    if( xResult == MQTTSuccess )
    {
        LogInfo( ( "Successfully created an MQTT connection with broker." ) );
        /* Resume a session if desired. */
        if( xCleanSession == false )
        {
            LogInfo( ( "Resuming previous MQTT session with broker." ) );
            xResult = MQTTAgent_ResumeSession( &xGlobalMqttAgentContext, xSessionPresent );
        }
    }
    else
    {
        LogError( ( "Failed to create an MQTT connect with broker, error = %d", xResult ) );
    }

    return xResult;
}

static BaseType_t prvSocketConnect( NetworkContext_t * pxNetworkContext )
{
    BaseType_t xConnected = pdFAIL;
    BackoffAlgorithmStatus_t xBackoffAlgStatus = BackoffAlgorithmSuccess;
    BackoffAlgorithmContext_t xReconnectParams = { 0 };
    uint16_t usNextRetryBackOff = 0U;

    TlsTransportStatus_t xNetworkStatus = TLS_TRANSPORT_CONNECT_FAILURE;
    NetworkCredentials_t xNetworkCredentials = { 0 };

    #ifdef democonfigUSE_AWS_IOT_CORE_BROKER

        /* ALPN protocols must be a NULL-terminated list of strings. Therefore,
         * the first entry will contain the actual ALPN protocol string while the
         * second entry must remain NULL. */
         const char * pcAlpnProtocols[] = { NULL, NULL };

         /* The ALPN string changes depending on whether username/password authentication is used. */
        #ifdef democonfigCLIENT_USERNAME
             pcAlpnProtocols[ 0 ] = AWS_IOT_CUSTOM_AUTH_ALPN;
        #else
             pcAlpnProtocols[ 0 ] = AWS_IOT_MQTT_ALPN;
        #endif
        xNetworkCredentials.pAlpnProtos = pcAlpnProtocols;
    #endif /* ifdef democonfigUSE_AWS_IOT_CORE_BROKER */

        /* Set the credentials for establishing a TLS connection. */
    xNetworkCredentials.pRootCa = ( unsigned char * ) democonfigROOT_CA_PEM;
    xNetworkCredentials.rootCaSize = sizeof( democonfigROOT_CA_PEM );
    xNetworkCredentials.pClientCertLabel = pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS;
    xNetworkCredentials.pPrivateKeyLabel = pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;

    xNetworkCredentials.disableSni = democonfigDISABLE_SNI;

       /* We will use a retry mechanism with an exponential backoff mechanism and
        * jitter.  That is done to prevent a fleet of IoT devices all trying to
        * reconnect at exactly the same time should they become disconnected at
        * the same time. We initialize reconnect attempts and interval here. */
    BackoffAlgorithm_InitializeParams( &xReconnectParams,
    		   RETRY_BACKOFF_BASE_MS,
			   RETRY_MAX_BACKOFF_DELAY_MS,
			   RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after a
     * timeout. Timeout value will exponentially increase until the maximum
     * number of attempts are reached.
     */
    do
    {
        /* Establish a TCP connection with the MQTT broker. This example connects to
         * the MQTT broker as specified in democonfigMQTT_BROKER_ENDPOINT and
         * democonfigMQTT_BROKER_PORT at the top of this file. */
            LogInfo( ( "Creating a TLS connection to %s:%u.",
                       pcBrokerEndpoint,
                       ulBrokerPort ) );
            xNetworkStatus = TLS_FreeRTOS_Connect( pxNetworkContext,
            		pcBrokerEndpoint,
					ulBrokerPort,
					&xNetworkCredentials,
					mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS,
					mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS );

            xConnected = ( xNetworkStatus == TLS_TRANSPORT_SUCCESS ) ? pdPASS : pdFAIL;

            if( !xConnected )
            {
            	/* Get back-off value (in milliseconds) for the next connection retry. */
            	xBackoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &xReconnectParams, xTaskGetTickCount(), &usNextRetryBackOff );

            	if( xBackoffAlgStatus == BackoffAlgorithmSuccess )
            	{
            		LogWarn( ( "Connection to the broker failed. "
            				"Retrying connection in %hu ms.",
							usNextRetryBackOff ) );
            		vTaskDelay( pdMS_TO_TICKS( usNextRetryBackOff ) );
            	} else if( xBackoffAlgStatus == BackoffAlgorithmRetriesExhausted )
                {
                    LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                } else {
                    /* Empty Else. */
                }
            }
            else
            {
                LogInfo( ( "TLS Connection to the broker succeeded." ) );
            }

    } while( ( xConnected != pdPASS ) && ( xBackoffAlgStatus == BackoffAlgorithmSuccess ) );

    return xConnected;
}

/*-----------------------------------------------------------*/

static BaseType_t prvSocketDisconnect( NetworkContext_t * pxNetworkContext )
{
    LogInfo( ( "Disconnecting TLS connection.\n" ) );
    TLS_FreeRTOS_Disconnect( pxNetworkContext );
    return pdPASS;
}

/*-----------------------------------------------------------*/

static void prvIncomingPublishCallback( MQTTAgentContext_t * pMqttAgentContext,
                                        uint16_t packetId,
                                        MQTTPublishInfo_t * pxPublishInfo )
{
    bool xPublishHandled = false;
    char cOriginalChar, * pcLocation;

    ( void ) packetId;

    /* Fan out the incoming publishes to the callbacks registered using
     * subscription manager. */
    xPublishHandled = SubscriptionStore_HandlePublish( ( SubscriptionStore_t * ) pMqttAgentContext->pIncomingCallbackContext,
                                               pxPublishInfo );

    /* If there are no callbacks to handle the incoming publishes,
     * handle it as an unsolicited publish. */
    if( xPublishHandled != true )
    {
        /* Ensure the topic string is terminated for printing.  This will over-
         * write the message ID, which is restored afterwards. */
        pcLocation = ( char * ) &( pxPublishInfo->pTopicName[ pxPublishInfo->topicNameLength ] );
        cOriginalChar = *pcLocation;
        *pcLocation = 0x00;
        LogWarn( ( "WARN:  Received an unsolicited publish from topic %s", pxPublishInfo->pTopicName ) );
        *pcLocation = cOriginalChar;
    }
}

/*-----------------------------------------------------------*/

BaseType_t xIsMQTTAgentRunning( void )
{
	BaseType_t xResult = pdFALSE;
	EventBits_t uxBits;


	uxBits = xEventGroupGetBits( xMQTTAgentEventGrp );

	if( ( uxBits & MQTT_AGENT_STARTED_EVENT_BIT ) == MQTT_AGENT_STARTED_EVENT_BIT )
	{
		xResult = pdTRUE;
	}

	return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t xWaitForMQTTAgentTask( uint32_t waitTimeMS )
{
	BaseType_t xResult = pdFALSE;
	TickType_t xWaitTicks;
	EventBits_t uxBits;

	if( waitTimeMS == 0U )
	{
		xWaitTicks = portMAX_DELAY;
	}
	else
	{
		xWaitTicks = pdMS_TO_TICKS( waitTimeMS );
	}

	uxBits = xEventGroupWaitBits( xMQTTAgentEventGrp,
			                  MQTT_AGENT_STARTED_EVENT_BIT,
							  pdFALSE,
							  pdTRUE,
							  xWaitTicks );

	if( ( uxBits & MQTT_AGENT_STARTED_EVENT_BIT ) == MQTT_AGENT_STARTED_EVENT_BIT )
	{
		xResult = pdTRUE;
	}

	return xResult;
}


/*-----------------------------------------------------------*/


BaseType_t xStartMQTTAgent( configSTACK_DEPTH_TYPE uxStackSize, UBaseType_t uxPriority )
{
	BaseType_t xResult = pdFAIL;

	xMQTTAgentEventGrp = xEventGroupCreate();

	if( xMQTTAgentEventGrp != NULL )
	{
		xResult = xTaskCreate( prvMQTTAgentTask,
				               "MQTT",
							   uxStackSize,
							   NULL,
							   uxPriority,
				               NULL );

	}

	return xResult;


}

/*-----------------------------------------------------------*/

void prvMQTTAgentTask( void * pvParameters )
{
	BaseType_t xStatus = pdFAIL;
    MQTTStatus_t xMQTTStatus = MQTTBadParameter;
    BaseType_t xConnected = pdFALSE;
    bool xReconnect = false;
    MQTTContext_t * pMqttContext = &( xGlobalMqttAgentContext.mqttContext );

    ( void ) pvParameters;

    /* Initialization of timestamp for MQTT. */
    ulGlobalEntryTimeMs = prvGetTimeMs();

    /* Load broker endpoint and thing name for client connection, from the key store. */
    xThingNameLength = KVStore_getValueLength( KVS_CORE_THING_NAME );
    if( xThingNameLength > 0 )
    {
    	pcThingName = pvPortMalloc( xThingNameLength + 1 );
    	if( pcThingName != NULL )
    	{
    		( void ) KVStore_getString( KVS_CORE_THING_NAME, pcThingName, ( xThingNameLength + 1 ) );
    		xStatus = pdPASS;
    	}
    	else
    	{
    		xStatus = pdFAIL;
    	}

    }
    else
    {
    	xStatus = pdFAIL;
    }

    if( xStatus == pdPASS )
    {
    	xBrokerEndpointLength = KVStore_getValueLength( KVS_CORE_MQTT_ENDPOINT );
    	if( xBrokerEndpointLength > 0 )
    	{
    		pcBrokerEndpoint = pvPortMalloc( xBrokerEndpointLength + 1 );
    		if( pcBrokerEndpoint != NULL )
    		{
    			( void ) KVStore_getString( KVS_CORE_MQTT_ENDPOINT, pcBrokerEndpoint, ( xBrokerEndpointLength + 1 ) );
    			xStatus = pdPASS;
    		}
    		else
    		{
    			xStatus = pdFAIL;
    		}

    	}
    	else
    	{
    		xStatus = pdFAIL;
    	}
    }

    if( xStatus == pdPASS )
    {
    	ulBrokerPort = KVStore_getUInt32( KVS_CORE_MQTT_PORT, &xStatus );
    }

    /* Initialize the MQTT context with the buffer and transport interface. */
    if( xStatus == pdPASS )
    {
    	xMQTTStatus = prvMQTTInit();
    }

     if( xMQTTStatus == MQTTSuccess )
     {
         do
         {
             xConnected = prvConnectToMQTTBroker( xReconnect );

             if( xConnected == pdTRUE )
             {
                 /* MQTTAgent_CommandLoop() is effectively the agent implementation.  It
                  * will manage the MQTT protocol until such time that an error occurs,
                  * which could be a disconnect.  If an error occurs the MQTT context on
                  * which the error happened is returned so there is an attempt to
                  * clean up and reconnect. */

                 pMqttContext->connectStatus = MQTTConnected;

                 ( void ) xEventGroupSetBits( xMQTTAgentEventGrp, MQTT_AGENT_STARTED_EVENT_BIT );

                 xMQTTStatus = MQTTAgent_CommandLoop( &xGlobalMqttAgentContext );

                 ( void ) xEventGroupClearBits( xMQTTAgentEventGrp, MQTT_AGENT_STARTED_EVENT_BIT );

                 if( xMQTTStatus == MQTTSuccess )
                 {
                     /* Success is returned for a graceful disconnect or termination. The socket should
                      * be disconnected and exit the loop. */
                     ( void ) prvSocketDisconnect( &xNetworkContext );
                     pMqttContext->connectStatus = MQTTNotConnected;
                     xReconnect = false;
                 }
                 else
                 {
                     /* MQTT agent returned due to an underlying error, reconnect to the loop. */
                     ( void ) prvSocketDisconnect( &xNetworkContext );
                     pMqttContext->connectStatus = MQTTNotConnected;
                     xReconnect = true;
                 }
             }
             else
             {
                 LogError(( "Failed to start MQTT agent loop, MQTT connect attempt failed." ));
                 xReconnect = false;
             }

         } while( xReconnect == true );
     }
     else
     {
         LogError(( "Failed to initialize MQTT." ));
     }

     if( pcThingName != NULL )
     {
    	 vPortFree( pcThingName );
    	 pcThingName = NULL;
    	 xThingNameLength = 0U;
     }

     if( pcBrokerEndpoint != NULL )
     {
    	 vPortFree( pcBrokerEndpoint );
    	 pcBrokerEndpoint = NULL;
    	 xBrokerEndpointLength = 0U;
     }


    vTaskDelete( NULL );
}

/*-----------------------------------------------------------*/

static BaseType_t prvConnectToMQTTBroker( bool xIsReconnect )
{
    BaseType_t xStatus = pdFAIL;
    MQTTStatus_t xMQTTStatus;

    /* Connect a TCP socket to the broker. */
    xStatus = prvSocketConnect( &xNetworkContext );

    if( xStatus == pdPASS )
    {
        xMQTTStatus = prvMQTTConnect( !xIsReconnect );
        if( xMQTTStatus != MQTTSuccess )
        {
            xStatus = pdFAIL;
        }
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static uint32_t prvGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) xTickCount * mqttexampleMILLISECONDS_PER_TICK;

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}

/*-----------------------------------------------------------*/

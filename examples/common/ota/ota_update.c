/*
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 * @file ota_over_mqtt_demo.c
 * @brief Over The Air Update demo using coreMQTT Agent.
 *
 * The file demonstrates how to perform Over The Air update using OTA agent and coreMQTT
 * library. It creates an OTA agent task which manages the OTA firmware update
 * for the device. The example also provides implementations to subscribe, publish,
 * and receive data from an MQTT broker. The implementation uses coreMQTT agent which manages
 * thread safety of the MQTT operations and allows OTA agent to share the same MQTT
 * broker connection with other tasks. OTA agent invokes the callback implementations to
 * publish job related control information, as well as receive chunks
 * of presigned firmware image from the MQTT broker.
 *
 * See https://freertos.org/mqtt/mqtt-agent-demo.html
 * See https://freertos.org/ota/ota-mqtt-agent-demo.html
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "ota_config.h"

/* MQTT library includes. */
#include "core_mqtt_agent.h"

/* MQTT streams Library include. */
#include "MQTTFileDownloader.h"
#include "MQTTFileDownloader_base64.h"

/* jobs Library include. */
#include "jobs.h"

/* OTA job parser include. */
#include "job_parser.h"
#include "ota_job_processor.h"

/* Include firmware version struct definition. */
/*#include "ota_appversion32.h" */

#include "ota_demo.h"
#include "ota_os_freertos.h"

#include "mqtt_wrapper.h"

/* Include platform abstraction header. */
#include "ota_pal.h"

/* Key Value store for fetching configuration info. */
#include "kvstore.h"

#include "mqtt_agent_task.h"

/*------------- Demo configurations -------------------------*/

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define otaexampleMAX_FILE_PATH_SIZE                     ( 260 )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define otaexampleMAX_STREAM_NAME_SIZE                   ( 128 )

/**
 * @brief The delay used in the OTA demo task to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define otaexampleTASK_DELAY_MS                          ( 5 * 1000U )

/**
 * @brief The maximum time for which OTA demo waits for an MQTT operation to be complete.
 * This involves receiving an acknowledgment for broker for SUBSCRIBE, UNSUBSCRIBE and non
 * QOS0 publishes.
 */
#define otaexampleMQTT_TIMEOUT_MS                        ( 10 * 1000U )

/**
 * @brief The common prefix for all OTA topics.
 *
 * Thing name is substituted with a wildcard symbol `+`. OTA agent
 * registers with MQTT broker with the thing name in the topic. This topic
 * filter is used to match incoming packet received and route them to OTA.
 * Thing name is not needed for this matching.
 */
#define OTA_TOPIC_PREFIX                                 "$aws/things"

/**
 * @brief Length of OTA topics prefix.
 */
#define OTA_PREFIX_LENGTH                                ( sizeof( OTA_TOPIC_PREFIX ) - 1UL )

/**
 * @brief Wildcard topic filter for job notification.
 * The filter is used to match the constructed job notify topic filter from OTA agent and register
 * appropriate callback for it.
 */
#define OTA_JOB_NOTIFY_TOPIC_FILTER                      OTA_TOPIC_PREFIX "/+/jobs/notify-next"

/**
 * @brief Length of job notification topic filter.
 */
#define OTA_JOB_NOTIFY_TOPIC_FILTER_LENGTH               ( ( uint16_t ) ( sizeof( OTA_JOB_NOTIFY_TOPIC_FILTER ) - 1UL ) )

/**
 * @brief Wildcard topic filter for matching job response messages.
 * This topic filter is used to match the responses from OTA service for OTA agent job requests. THe
 * topic filter is a reserved topic which is not subscribed with MQTT broker.
 *
 */
#define OTA_JOB_ACCEPTED_RESPONSE_TOPIC_FILTER           OTA_TOPIC_PREFIX "/+/jobs/$next/get/accepted"

/**
 * @brief Length of job accepted response topic filter.
 */
#define OTA_JOB_ACCEPTED_RESPONSE_TOPIC_FILTER_LENGTH    ( ( uint16_t ) ( sizeof( OTA_JOB_ACCEPTED_RESPONSE_TOPIC_FILTER ) - 1 ) )


/**
 * @brief Wildcard topic filter for matching OTA data packets.
 *  The filter is used to match the constructed data stream topic filter from OTA agent and register
 * appropriate callback for it.
 */
#define OTA_DATA_STREAM_TOPIC_FILTER           OTA_TOPIC_PREFIX "/+/streams/#"

/**
 * @brief Length of data stream topic filter.
 */
#define OTA_DATA_STREAM_TOPIC_FILTER_LENGTH    ( ( uint16_t ) ( sizeof( OTA_DATA_STREAM_TOPIC_FILTER ) - 1 ) )


/**
 * @brief Starting index of client identifier within OTA topic.
 */
#define OTA_TOPIC_CLIENT_IDENTIFIER_START_IDX    ( OTA_PREFIX_LENGTH + 1 )

/**
 * @brief Used to clear bits in a task's notification value.
 */
#define otaexampleMAX_UINT32                     ( 0xffffffff )

/**
 * @brief Task priority of OTA agent.
 */
#define otaexampleAGENT_TASK_PRIORITY            ( tskIDLE_PRIORITY + 2 )

/**
 * @brief Maximum stack size of OTA agent task.
 */
#define otaexampleAGENT_TASK_STACK_SIZE          ( 4096 * 2 )


#define CONFIG_MAX_FILE_SIZE                     200 /* TODO:!! */
#define NUM_OF_BLOCKS_REQUESTED                  1U
#define START_JOB_MSG_LENGTH                     147U
#define MAX_THING_NAME_SIZE                      128U
#define MAX_JOB_ID_LENGTH                        64U
#define UPDATE_JOB_MSG_LENGTH                    48U
#define MAX_NUM_OF_OTA_DATA_BUFFERS              2U

/* Max bytes supported for a file signature (3072 bit RSA is 384 bytes). */
#define OTA_MAX_SIGNATURE_SIZE                   ( 384U )

/**
 * @brief Defines the structure to use as the command callback context in this
 * demo.
 */
struct MQTTAgentCommandContext
{
    TaskHandle_t xTaskToNotify;
    void * pArgs;
};

static MqttFileDownloaderContext_t mqttFileDownloaderContext = { 0 };
static uint32_t numOfBlocksRemaining = 0;
static uint32_t currentBlockOffset = 0;
static uint8_t currentFileId = 0;
static uint32_t totalBytesReceived = 0;
char globalJobId[ MAX_JOB_ID_LENGTH ] = { 0 };

static SemaphoreHandle_t bufferSemaphore;

static OtaDataEvent_t dataBuffers[ MAX_NUM_OF_OTA_DATA_BUFFERS ] = { 0 };
static OtaJobEventData_t jobDocBuffer = { 0 };
static AfrOtaJobDocumentFields_t jobFields = { 0 };
static uint8_t OtaImageSingatureDecoded[ OTA_MAX_SIGNATURE_SIZE ] = { 0 };
static SemaphoreHandle_t bufferSemaphore;

static OtaState_t otaAgentState = OtaAgentStateInit;

/**
 * @brief The function which runs the OTA agent task.
 *
 * The function runs the OTA Agent Event processing loop, which waits for
 * any events for OTA agent and process them. The loop never returns until the OTA agent
 * is shutdown. The tasks exits gracefully by freeing up all resources in the event of an
 *  OTA agent shutdown.
 *
 * @param[in] pvParam Any parameters to be passed to OTA agent task.
 */
static void prvOTAAgentTask( void * pvParam );


/**
 * @brief The function which runs the OTA update task.
 *
 * The demo task initializes the OTA agent an loops until OTA agent is shutdown.
 * It reports OTA update statistics (which includes number of blocks received, processed and dropped),
 * at regular intervals.
 *
 * @param[in] pvParam Any parameters to be passed to OTA demo task.
 */
void vOTAUpdateTask( void * pvParam );

/**
 * @brief This is in essence the OTA agent implementation.
 */
static void processOTAEvents( void );

/**
 * @brief
 */
static bool imageActivationHandler( void );

/**
 * @brief
 */
static bool closeFileHandler( void );

/**
 * @brief
 */
static OtaPalJobDocProcessingResult_t receivedJobDocumentHandler( OtaJobEventData_t * jobDoc );

/**
 * @brief
 */
static uint16_t getFreeOTABuffers( void );

/**
 * @brief
 */
static void freeOtaDataEventBuffer( OtaDataEvent_t * const pxBuffer );

/**
 * @brief
 */
static OtaDataEvent_t * getOtaDataEventBuffer( void );

/**
 * @brief
 */
static void requestDataBlock( void );

/**
 * @brief
 */
static int16_t handleMqttStreamsBlockArrived( uint8_t * data,
                                              size_t dataLength );

/**
 * @brief
 */
static bool convertSignatureToDER( AfrOtaJobDocumentFields_t * jobFields );

/**
 * @brief
 */
static void initMqttDownloader( AfrOtaJobDocumentFields_t * jobFields );

/**
 * @brief
 */
static void requestJobDocumentHandler( void );

/**
 * @brief
 */
static bool jobDocumentParser( char * message,
                               size_t messageLength,
                               AfrOtaJobDocumentFields_t * jobFields );


/**
 * @brief
 */
static bool sendSuccessMessage( void );


/*
 * @brief Mutex used to manage thread safe access of OTA event buffers.
 */
static SemaphoreHandle_t xBufferSemaphore;

/**
 * @brief Static handle used for MQTT agent context.
 */
extern MQTTAgentContext_t xGlobalMqttAgentContext;


/**
 * @brief Structure used for encoding firmware version.
 */
const AppVersion32_t appFirmwareVersion =
{
    .u.x.major = APP_VERSION_MAJOR,
    .u.x.minor = APP_VERSION_MINOR,
    .u.x.build = APP_VERSION_BUILD,
};

/*
 * @brief The thing name used for creating OTA job topics.
 * Thing name is retrieved from a key value store.
 */
static char * pcThingName = NULL;
static size_t xThingNameLength = 0U;

/*-----------------------------------------------------------*/

static void prvOTAAgentTask( void * pvParam )
{
    BaseType_t xResult;
    size_t xValueLength = 0U;
    char * pcValue = NULL;

    LogError( "Running OTA Agent task. Waiting..." );

    while( 1 )
    {
        xResult = xWaitForMQTTAgentState( MQTT_AGENT_STATE_CONNECTED,
                                          portMAX_DELAY );

        if( xResult == pdTRUE )
        {
            break;
        }
    }

    /* Load broker thing name from the key store. */
    xValueLength = KVStore_getValueLength( KVS_CORE_THING_NAME );

    if( xValueLength > 0 )
    {
        pcValue = pvPortMalloc( xValueLength + 1 );

        if( pcValue != NULL )
        {
            ( void ) KVStore_getString( KVS_CORE_THING_NAME, pcValue, ( xValueLength + 1 ) );
        }
    }

    mqttWrapper_setThingName( pcValue, xValueLength );

    vPortFree( pcValue );

    otaDemo_start();

    vTaskDelete( NULL );
}

/*-----------------------------------------------------------*/

void otaDemo_start( void )
{
    OtaEventMsg_t initEvent = { 0 };

    if( !mqttWrapper_isConnected() )
    {
        LogInfo( "MQTT not connected, exiting!" );
        return;
    }

    bufferSemaphore = xSemaphoreCreateMutex();

    if( bufferSemaphore != NULL )
    {
        memset( dataBuffers, 0x00, sizeof( dataBuffers ) );
    }

    LogError( "Starting OTA thread." );

    OtaInitEvent_FreeRTOS();

    initEvent.eventId = OtaAgentEventRequestJobDocument;
    OtaSendEvent_FreeRTOS( &initEvent );

    while( otaAgentState != OtaAgentStateStopped )
    {
        processOTAEvents();
    }
}

/*-----------------------------------------------------------*/

static void requestJobDocumentHandler( void )
{
    char thingName[ MAX_THING_NAME_SIZE + 1 ] = { 0 };
    size_t thingNameLength = 0U;
    char topicBuffer[ TOPIC_BUFFER_SIZE + 1 ] = { 0 };
    char messageBuffer[ START_JOB_MSG_LENGTH ] = { 0 };
    size_t topicLength = 0U;

    mqttWrapper_getThingName( thingName, &thingNameLength );

    /*
     * AWS IoT Jobs library:
     * Creates the topic string for a StartNextPendingJobExecution request.
     * It used to check if any pending jobs are available.
     */
    Jobs_StartNext( topicBuffer,
                    TOPIC_BUFFER_SIZE,
                    thingName,
                    ( uint16_t ) thingNameLength,
                    &topicLength );

    /*
     * AWS IoT Jobs library:
     * Creates the message string for a StartNextPendingJobExecution request.
     * It will be sent on the topic created in the previous step.
     */
    size_t messageLength = Jobs_StartNextMsg( "test",
                                              4U,
                                              messageBuffer,
                                              START_JOB_MSG_LENGTH );

    mqttWrapper_publish( topicBuffer,
                         topicLength,
                         ( uint8_t * ) messageBuffer,
                         messageLength );
}

/*-----------------------------------------------------------*/

static void initMqttDownloader( AfrOtaJobDocumentFields_t * jobFields )
{
    char thingName[ MAX_THING_NAME_SIZE + 1 ] = { 0 };
    size_t thingNameLength = 0U;

    numOfBlocksRemaining = jobFields->fileSize /
                           mqttFileDownloader_CONFIG_BLOCK_SIZE;
    numOfBlocksRemaining += ( jobFields->fileSize %
                              mqttFileDownloader_CONFIG_BLOCK_SIZE > 0 ) ? 1 : 0;
    currentFileId = ( uint8_t ) jobFields->fileId;
    currentBlockOffset = 0;
    totalBytesReceived = 0;

    mqttWrapper_getThingName( thingName, &thingNameLength );

    /*
     * MQTT streams Library:
     * Initializing the MQTT streams downloader. Passing the
     * parameters extracted from the AWS IoT OTA jobs document
     * using OTA jobs parser.
     */
    mqttDownloader_init( &mqttFileDownloaderContext,
                         jobFields->imageRef,
                         jobFields->imageRefLen,
                         thingName,
                         thingNameLength,
                         DATA_TYPE_JSON );

    mqttWrapper_subscribe( mqttFileDownloaderContext.topicStreamData,
                           mqttFileDownloaderContext.topicStreamDataLength );
}

/*-----------------------------------------------------------*/

static bool convertSignatureToDER( AfrOtaJobDocumentFields_t * jobFields )
{
    bool returnVal = true;
    size_t decodedSignatureLength = 0;


    Base64Status_t xResult = base64_Decode( OtaImageSingatureDecoded,
                                            sizeof( OtaImageSingatureDecoded ),
                                            &decodedSignatureLength,
                                            jobFields->signature,
                                            jobFields->signatureLen );

    if( xResult == Base64Success )
    {
        jobFields->signature = OtaImageSingatureDecoded;
        jobFields->signatureLen = decodedSignatureLength;
    }
    else
    {
        returnVal = false;
    }

    return returnVal;
}

/*-----------------------------------------------------------*/

static int16_t handleMqttStreamsBlockArrived( uint8_t * data,
                                              size_t dataLength )
{
    int16_t writeblockRes = -1;

    LogInfo( "Downloaded block %u of %u. \n", currentBlockOffset, ( currentBlockOffset + numOfBlocksRemaining ) );

    writeblockRes = otaPal_WriteBlock( &jobFields,
                                       totalBytesReceived,
                                       data,
                                       dataLength );

    if( writeblockRes > 0 )
    {
        totalBytesReceived += writeblockRes;
    }

    return writeblockRes;
}

/*-----------------------------------------------------------*/

static void requestDataBlock( void )
{
    char getStreamRequest[ GET_STREAM_REQUEST_BUFFER_SIZE ];
    size_t getStreamRequestLength = 0U;

    /*
     * MQTT streams Library:
     * Creating the Get data block request. MQTT streams library only
     * creates the get block request. To publish the request, MQTT libraries
     * like coreMQTT are required.
     */
    getStreamRequestLength = mqttDownloader_createGetDataBlockRequest( mqttFileDownloaderContext.dataType,
                                                                       currentFileId,
                                                                       mqttFileDownloader_CONFIG_BLOCK_SIZE,
                                                                       ( uint16_t ) currentBlockOffset,
                                                                       NUM_OF_BLOCKS_REQUESTED,
                                                                       getStreamRequest,
                                                                       GET_STREAM_REQUEST_BUFFER_SIZE );

    mqttWrapper_publish( mqttFileDownloaderContext.topicGetStream,
                         mqttFileDownloaderContext.topicGetStreamLength,
                         ( uint8_t * ) getStreamRequest,
                         getStreamRequestLength );
}

/*-----------------------------------------------------------*/

static bool closeFileHandler( void )
{
    return( OtaPalSuccess == otaPal_CloseFile( &jobFields ) );
}

/*-----------------------------------------------------------*/

static bool imageActivationHandler( void )
{
    return( OtaPalSuccess == otaPal_ActivateNewImage( &jobFields ) );
}

/*-----------------------------------------------------------*/

static OtaPalJobDocProcessingResult_t receivedJobDocumentHandler( OtaJobEventData_t * jobDoc )
{
    bool parseJobDocument = false;
    bool handled = false;
    char * jobId;
    const char ** jobIdptr = &jobId;
    size_t jobIdLength = 0U;
    OtaPalJobDocProcessingResult_t xResult = OtaPalJobDocFileCreateFailed;

    memset( &jobFields, 0, sizeof( jobFields ) );

    /*
     * AWS IoT Jobs library:
     * Extracting the job ID from the received OTA job document.
     */
    jobIdLength = Jobs_GetJobId( ( char * ) jobDoc->jobData, jobDoc->jobDataLength, jobIdptr );

    if( jobIdLength )
    {
        if( strncmp( globalJobId, jobId, jobIdLength ) )
        {
            parseJobDocument = true;
            strncpy( globalJobId, jobId, jobIdLength );
        }
        else
        {
            xResult = OtaPalJobDocFileCreated;
        }
    }

    if( parseJobDocument )
    {
        handled = jobDocumentParser( ( char * ) jobDoc->jobData, jobDoc->jobDataLength, &jobFields );

        if( handled )
        {
            initMqttDownloader( &jobFields );

            /* AWS IoT core returns the signature in a PEM format. We need to
             * convert it to DER format for image signature verification. */

            handled = convertSignatureToDER( &jobFields );

            if( handled )
            {
                xResult = otaPal_CreateFileForRx( &jobFields );
            }
            else
            {
                LogError( "Failed to decode the image signature to DER format." );
            }
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/

static uint16_t getFreeOTABuffers( void )
{
    uint32_t ulIndex = 0;
    uint16_t freeBuffers = 0;

    if( xSemaphoreTake( bufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < MAX_NUM_OF_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( dataBuffers[ ulIndex ].bufferUsed == false )
            {
                freeBuffers++;
            }
        }

        ( void ) xSemaphoreGive( bufferSemaphore );
    }
    else
    {
        LogInfo( "Failed to get buffer semaphore. \n" );
    }

    return freeBuffers;
}

/*-----------------------------------------------------------*/

static void freeOtaDataEventBuffer( OtaDataEvent_t * const pxBuffer )
{
    if( xSemaphoreTake( bufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        pxBuffer->bufferUsed = false;
        ( void ) xSemaphoreGive( bufferSemaphore );
    }
    else
    {
        LogInfo( "Failed to get buffer semaphore.\n" );
    }
}

/*-----------------------------------------------------------*/

/* Implemented for use by the MQTT library */
bool otaDemo_handleIncomingMQTTMessage( char * topic,
                                        size_t topicLength,
                                        uint8_t * message,
                                        size_t messageLength )
{
    OtaEventMsg_t nextEvent = { 0 };
    char thingName[ MAX_THING_NAME_SIZE + 1 ] = { 0 };
    size_t thingNameLength = 0U;

    /*
     * MQTT streams Library:
     * Checks if the incoming message contains the requested data block. It is performed by
     * comparing the incoming MQTT message topic with MQTT streams topics.
     */
    bool handled = mqttDownloader_isDataBlockReceived( &mqttFileDownloaderContext, topic, topicLength );

    if( handled )
    {
        nextEvent.eventId = OtaAgentEventReceivedFileBlock;
        OtaDataEvent_t * dataBuf = getOtaDataEventBuffer();
        memcpy( dataBuf->data, message, messageLength );
        nextEvent.dataEvent = dataBuf;
        dataBuf->dataLength = messageLength;
        OtaSendEvent_FreeRTOS( &nextEvent );
    }
    else
    {
        mqttWrapper_getThingName( thingName, &thingNameLength );

        /*
         * AWS IoT Jobs library:
         * Checks if a message comes from the start-next/accepted reserved topic.
         */
        handled = Jobs_IsStartNextAccepted( topic,
                                            topicLength,
                                            thingName,
                                            thingNameLength );

        if( handled )
        {
            memcpy( jobDocBuffer.jobData, message, messageLength );
            nextEvent.jobEvent = &jobDocBuffer;
            jobDocBuffer.jobDataLength = messageLength;
            nextEvent.eventId = OtaAgentEventReceivedJobDocument;
            OtaSendEvent_FreeRTOS( &nextEvent );
        }
    }

    return handled;
}

/*-----------------------------------------------------------*/

static bool sendSuccessMessage( void )
{
    char thingName[ MAX_THING_NAME_SIZE + 1 ] = { 0 };
    size_t thingNameLength = 0U;
    char topicBuffer[ TOPIC_BUFFER_SIZE + 1 ] = { 0 };
    size_t topicBufferLength = 0U;
    char messageBuffer[ UPDATE_JOB_MSG_LENGTH ] = { 0 };
    bool result = true;
    JobsStatus_t jobStatusResult;

    mqttWrapper_getThingName( thingName, &thingNameLength );

    /*
     * AWS IoT Jobs library:
     * Creating the MQTT topic to update the status of OTA job.
     */
    jobStatusResult = Jobs_Update( topicBuffer,
                                   TOPIC_BUFFER_SIZE,
                                   thingName,
                                   ( uint16_t ) thingNameLength,
                                   globalJobId,
                                   ( uint16_t ) strnlen( globalJobId, 1000U ),
                                   &topicBufferLength );

    if( jobStatusResult == JobsSuccess )
    {
        /*
         * AWS IoT Jobs library:
         * Creating the message which contains the status of OTA job.
         * It will be published on the topic created in the previous step.
         */
        size_t messageBufferLength = Jobs_UpdateMsg( Succeeded,
                                                     "2",
                                                     1U,
                                                     messageBuffer,
                                                     UPDATE_JOB_MSG_LENGTH );

        result = mqttWrapper_publish( topicBuffer,
                                      topicBufferLength,
                                      ( uint8_t * ) messageBuffer,
                                      messageBufferLength );

        LogInfo( "\033[1;32mOTA Completed successfully!\033[0m\n" );
        globalJobId[ 0 ] = 0U;

        /* Clean up the job doc buffer so that it is ready for when we
         * receive new job doc. */
        memset( &jobDocBuffer, 0, sizeof( jobDocBuffer ) );
    }
    else
    {
        result = false;
    }

    return result;
}

/*-----------------------------------------------------------*/

static bool jobDocumentParser( char * message,
                               size_t messageLength,
                               AfrOtaJobDocumentFields_t * jobFields )
{
    const char * jobDoc;
    size_t jobDocLength = 0U;
    int8_t fileIndex = 0;

    /*
     * AWS IoT Jobs library:
     * Extracting the OTA job document from the jobs message recevied from AWS IoT core.
     */
    jobDocLength = Jobs_GetJobDocument( message, messageLength, &jobDoc );

    if( jobDocLength != 0U )
    {
        do
        {
            /*
             * AWS IoT Jobs library:
             * Parsing the OTA job document to extract all of the parameters needed to download
             * the new firmware.
             */
            fileIndex = otaParser_parseJobDocFile( jobDoc,
                                                   jobDocLength,
                                                   fileIndex,
                                                   jobFields );
        } while( fileIndex > 0 );
    }

    /* File index will be -1 if an error occured, and 0 if all files were
     * processed. */
    return fileIndex == 0;
}

/*-----------------------------------------------------------*/

static OtaDataEvent_t * getOtaDataEventBuffer( void )
{
    uint32_t ulIndex = 0;
    OtaDataEvent_t * freeBuffer = NULL;

    if( xSemaphoreTake( bufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < MAX_NUM_OF_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( dataBuffers[ ulIndex ].bufferUsed == false )
            {
                dataBuffers[ ulIndex ].bufferUsed = true;
                freeBuffer = &dataBuffers[ ulIndex ];
                break;
            }
        }

        ( void ) xSemaphoreGive( bufferSemaphore );
    }
    else
    {
        LogInfo( "Failed to get buffer semaphore. \n" );
    }

    return freeBuffer;
}

/*-----------------------------------------------------------*/

static void processOTAEvents( void )
{
    OtaEventMsg_t recvEvent = { 0 };
    OtaEvent_t recvEventId = 0;
    static OtaEvent_t lastRecvEventId = OtaAgentEventStart;
    OtaEventMsg_t nextEvent = { 0 };

    OtaReceiveEvent_FreeRTOS( &recvEvent );
    recvEventId = recvEvent.eventId;

    if( recvEventId != OtaAgentEventStart )
    {
        lastRecvEventId = recvEventId;
    }
    else
    {
        if( lastRecvEventId == OtaAgentEventRequestFileBlock )
        {
            /* No current event and we have not received the new block
             * since last timeout, try sending the request for block again. */
            recvEventId = lastRecvEventId;

            /* It is likely that the network was disconnected and reconnected,
             * we should wait for the MQTT connection to go up. */
            while( !mqttWrapper_isConnected() )
            {
                vTaskDelay( pdMS_TO_TICKS( 100 ) );
            }
        }
    }

    switch( recvEventId )
    {
        case OtaAgentEventRequestJobDocument:
            LogInfo( "Request Job Document event Received \n" );
            LogInfo( "-------------------------------------\n" );
            requestJobDocumentHandler();
            otaAgentState = OtaAgentStateRequestingJob;
            break;

        case OtaAgentEventReceivedJobDocument:
            LogInfo( "Received Job Document event Received \n" );
            LogInfo( "-------------------------------------\n" );

            if( otaAgentState == OtaAgentStateSuspended )
            {
                LogInfo( "OTA-Agent is in Suspend State. Hence dropping Job Document. \n" );
                break;
            }

            switch( receivedJobDocumentHandler( recvEvent.jobEvent ) )
            {
                case OtaPalJobDocFileCreated:
                    LogInfo( "Received OTA Job. \n" );
                    nextEvent.eventId = OtaAgentEventRequestFileBlock;
                    OtaSendEvent_FreeRTOS( &nextEvent );
                    otaAgentState = OtaAgentStateCreatingFile;
                    break;

                case OtaPalJobDocFileCreateFailed:
                case OtaPalNewImageBootFailed:
                case OtaPalJobDocProcessingStateInvalid:
                    LogInfo( "This is not an OTA job \n" );
                    break;

                case OtaPalNewImageBooted:
                    ( void ) sendSuccessMessage();

                    /* Short delay before restarting the loop. This allows IoT core
                     * to update the status of the job. */
                    vTaskDelay( pdMS_TO_TICKS( 5000 ) );

                    /* Get ready for new OTA job. */
                    nextEvent.eventId = OtaAgentEventRequestJobDocument;
                    OtaSendEvent_FreeRTOS( &nextEvent );
                    break;
            }

            break;

        case OtaAgentEventRequestFileBlock:
            otaAgentState = OtaAgentStateRequestingFileBlock;
            LogInfo( "Request File Block event Received \n" );
            LogInfo( "-----------------------------------\n" );

            if( currentBlockOffset == 0 )
            {
                LogInfo( "Starting The Download. \n" );
            }

            requestDataBlock();
            LogInfo( "ReqSent----------------------------\n" );
            break;

        case OtaAgentEventReceivedFileBlock:
            LogInfo( "Received File Block event Received \n" );
            LogInfo( "---------------------------------------\n" );

            if( otaAgentState == OtaAgentStateSuspended )
            {
                LogInfo( "OTA-Agent is in Suspend State. Hence dropping File Block. \n" );
                freeOtaDataEventBuffer( recvEvent.dataEvent );
                break;
            }

            uint8_t decodedData[ mqttFileDownloader_CONFIG_BLOCK_SIZE ];
            size_t decodedDataLength = 0;
            MQTTFileDownloaderStatus_t xReturnStatus;
            int16_t result = -1;
            int32_t fileId;
            int32_t blockId;
            int32_t blockSize;
            static int32_t lastReceivedblockId = -1;

            /*
             * MQTT streams Library:
             * Extracting and decoding the received data block from the incoming MQTT message.
             */
            xReturnStatus = mqttDownloader_processReceivedDataBlock(
                &mqttFileDownloaderContext,
                recvEvent.dataEvent->data,
                recvEvent.dataEvent->dataLength,
                &fileId,
                &blockId,
                &blockSize,
                decodedData,
                &decodedDataLength );

            if( xReturnStatus != MQTTFileDownloaderSuccess )
            {
                /* There was some failure in trying to decode the block. */
            }
            else if( fileId != jobFields.fileId )
            {
                /* Error - the file ID doesn't match with the one we received in the job document. */
            }
            else if( blockSize > mqttFileDownloader_CONFIG_BLOCK_SIZE )
            {
                /* Error - the block size doesn't match with what we requested. It can be smaller as
                 * the last block may or may not be of exact size. */
            }
            else if( blockId <= lastReceivedblockId )
            {
                /* Ignore this block. */
            }
            else
            {
                result = handleMqttStreamsBlockArrived( decodedData, decodedDataLength );
                lastReceivedblockId = blockId;
            }

            freeOtaDataEventBuffer( recvEvent.dataEvent );

            if( result > 0 )
            {
                numOfBlocksRemaining--;
                currentBlockOffset++;
            }

            if( ( numOfBlocksRemaining % 10 ) == 0 )
            {
                LogInfo( "Free OTA buffers %u", getFreeOTABuffers() );
            }

            if( numOfBlocksRemaining == 0 )
            {
                nextEvent.eventId = OtaAgentEventCloseFile;
                OtaSendEvent_FreeRTOS( &nextEvent );
            }
            else
            {
                if( currentBlockOffset % NUM_OF_BLOCKS_REQUESTED == 0 )
                {
                    nextEvent.eventId = OtaAgentEventRequestFileBlock;
                    OtaSendEvent_FreeRTOS( &nextEvent );
                }
            }

            break;

        case OtaAgentEventCloseFile:
            LogInfo( "Close file event Received \n" );
            LogInfo( "-----------------------\n" );

            if( closeFileHandler() == true )
            {
                nextEvent.eventId = OtaAgentEventActivateImage;
                OtaSendEvent_FreeRTOS( &nextEvent );
            }

            break;

        case OtaAgentEventActivateImage:
            LogInfo( "Activate Image event Received \n" );
            LogInfo( "-----------------------\n" );

            if( imageActivationHandler() == true )
            {
                nextEvent.eventId = OtaAgentEventActivateImage;
                OtaSendEvent_FreeRTOS( &nextEvent );
            }

            otaAgentState = OtaAgentStateStopped;
            break;


        case OtaAgentEventSuspend:
            LogInfo( "Suspend Event Received \n" );
            LogInfo( "-----------------------\n" );
            otaAgentState = OtaAgentStateSuspended;
            break;

        case OtaAgentEventResume:
            LogInfo( "Resume Event Received \n" );
            LogInfo( "---------------------\n" );
            otaAgentState = OtaAgentStateRequestingJob;
            nextEvent.eventId = OtaAgentEventRequestJobDocument;
            OtaSendEvent_FreeRTOS( &nextEvent );

        default:
            break;
    }
}

/*-----------------------------------------------------------*/

void vOTAUpdateTask( void * pvParam )
{
    /* FreeRTOS APIs return status. */
    BaseType_t xResult = pdPASS;

    ( void ) pvParam;

    LogInfo( ( "OTA over MQTT demo, Application version %u.%u.%u",
               appFirmwareVersion.u.x.major,
               appFirmwareVersion.u.x.minor,
               appFirmwareVersion.u.x.build ) );
    /****************************** Init OTA Library. ******************************/


    xBufferSemaphore = xSemaphoreCreateMutex();

    if( xBufferSemaphore == NULL )
    {
        xResult = pdFAIL;
    }

    if( xResult == pdPASS )
    {
        xThingNameLength = KVStore_getValueLength( KVS_CORE_THING_NAME );

        if( xThingNameLength > 0 )
        {
            pcThingName = pvPortMalloc( xThingNameLength + 1 );

            if( pcThingName != NULL )
            {
                ( void ) KVStore_getString( KVS_CORE_THING_NAME, pcThingName, ( xThingNameLength + 1 ) );
                xResult = pdPASS;
            }
            else
            {
                xResult = pdFAIL;
            }
        }
        else
        {
            xResult = pdFAIL;
        }
    }

    if( xResult == pdPASS )
    {
        if( ( xResult = xTaskCreate( prvOTAAgentTask,
                                     "OTAAgent",
                                     otaexampleAGENT_TASK_STACK_SIZE,
                                     NULL,
                                     otaexampleAGENT_TASK_PRIORITY,
                                     NULL ) ) != pdPASS )
        {
            LogError( ( "Failed to start OTA Agent task: "
                        ",errno=%d",
                        xResult ) );
        }
    }

    vTaskDelay( portMAX_DELAY );

    LogInfo( ( "OTA agent task stopped. Exiting OTA demo." ) );

    if( pcThingName != NULL )
    {
        vPortFree( pcThingName );
        pcThingName = NULL;
        xThingNameLength = 0U;
    }

    vTaskDelete( NULL );
}

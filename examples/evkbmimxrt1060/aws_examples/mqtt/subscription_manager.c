/*
 * FreeRTOS V202011.00
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
 * https://aws.amazon.com/freertos
 *
 */

/**
 * @file subscription_manager.c
 * @brief Functions for managing MQTT subscriptions.
 */

/* Standard includes. */
#include <string.h>
#include "FreeRTOS.h"
#include "semphr.h"

/* Subscription manager header include. */
#include "subscription_manager.h"

/**
 * @brief An element in the list of subscriptions.
 *
 * This subscription manager implementation expects that the array of the
 * subscription elements used for storing subscriptions to be initialized to 0.
 *
 * @note This implementation allows multiple tasks to subscribe to the same topic.
 * In this case, another element is added to the subscription list, differing
 * in the intended publish callback. Also note that the topic filters are not
 * copied in the subscription manager and hence the topic filter strings need to
 * stay in scope until unsubscribed.
 */
typedef struct subscriptionElement
{
    IncomingPubCallback_t pxIncomingPublishCallback;
    void * pvIncomingPublishCallbackContext;
    uint16_t usFilterStringLength;
    const char * pcSubscriptionFilterString;
} SubscriptionElement_t;

typedef struct SubscriptionStore
{
	SubscriptionElement_t subscriptionList[ SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS ];
	SemaphoreHandle_t mutex;

}SubscriptionStore_t;


SubscriptionStore_t xGlobalSubscriptionStore;

SubscriptionStore_t * SubscriptionStore_Create( void )
{
	SubscriptionStore_t * pxStore = NULL;
	xGlobalSubscriptionStore.mutex = xSemaphoreCreateMutex();
	if( xGlobalSubscriptionStore.mutex != NULL )
	{
		pxStore = &xGlobalSubscriptionStore;
	}

	return pxStore;

}

bool SubscriptionStore_Add( SubscriptionStore_t * pxStore,
                      const char * pcTopicFilterString,
                      uint16_t usTopicFilterLength,
                      IncomingPubCallback_t pxIncomingPublishCallback,
                      void * pvIncomingPublishCallbackContext )
{
    int32_t lIndex = 0;
    size_t xAvailableIndex = SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS;
    bool xReturnStatus = false;

    if( ( pxStore == NULL ) ||
        ( pcTopicFilterString == NULL ) ||
        ( usTopicFilterLength == 0U ) ||
        ( pxIncomingPublishCallback == NULL ) )
    {
        LogError( ( "Invalid parameter. pxStore=%p, pcTopicFilterString=%p,"
                    " usTopicFilterLength=%u, pxIncomingPublishCallback=%p.",
					pxStore,
                    pcTopicFilterString,
                    ( unsigned int ) usTopicFilterLength,
                    pxIncomingPublishCallback ) );
    }
    else
    {
    	xSemaphoreTake( xGlobalSubscriptionStore.mutex, portMAX_DELAY );
    	{
    		/* Start at end of array, so that we will insert at the first available index.
    		 * Scans backwards to find duplicates. */
    		for( lIndex = ( int32_t ) SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS - 1; lIndex >= 0; lIndex-- )
    		{
    			if( pxStore->subscriptionList[ lIndex ].usFilterStringLength == 0 )
    			{
    				xAvailableIndex = lIndex;
    			}
    			else if( ( pxStore->subscriptionList[ lIndex ].usFilterStringLength == usTopicFilterLength ) &&
    					( strncmp( pcTopicFilterString, pxStore->subscriptionList[ lIndex ].pcSubscriptionFilterString, ( size_t ) usTopicFilterLength ) == 0 ) )
    			{
    				/* If a subscription already exists, don't do anything. */
    				if( ( pxStore->subscriptionList[ lIndex ].pxIncomingPublishCallback == pxIncomingPublishCallback ) &&
    						( pxStore->subscriptionList[ lIndex ].pvIncomingPublishCallbackContext == pvIncomingPublishCallbackContext ) )
    				{
    					LogWarn( ( "Subscription already exists.\n" ) );
    					xAvailableIndex = SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS;
    					xReturnStatus = true;
    					break;
    				}
    			}
    		}

    		if( xAvailableIndex < SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS )
    		{
    			pxStore->subscriptionList[ xAvailableIndex ].pcSubscriptionFilterString = pcTopicFilterString;
    			pxStore->subscriptionList[ xAvailableIndex ].usFilterStringLength = usTopicFilterLength;
    			pxStore->subscriptionList[ xAvailableIndex ].pxIncomingPublishCallback = pxIncomingPublishCallback;
    			pxStore->subscriptionList[ xAvailableIndex ].pvIncomingPublishCallbackContext = pvIncomingPublishCallbackContext;
    			xReturnStatus = true;
    		}
    	}
    	xSemaphoreGive( xGlobalSubscriptionStore.mutex );
    }

    return xReturnStatus;
}

/*-----------------------------------------------------------*/

void SubscriptionStore_Remove( SubscriptionStore_t * pxStore,
                         const char * pcTopicFilterString,
                         uint16_t usTopicFilterLength )
{
    uint32_t ulIndex = 0;

    if( ( pxStore == NULL ) ||
        ( pcTopicFilterString == NULL ) ||
        ( usTopicFilterLength == 0U ) )
    {
        LogError( ( "Invalid parameter. pxStore=%p, pcTopicFilterString=%p,"
                    " usTopicFilterLength=%u.",
					pxStore,
                    pcTopicFilterString,
                    ( unsigned int ) usTopicFilterLength ) );
    }
    else
    {
    	xSemaphoreTake( xGlobalSubscriptionStore.mutex, portMAX_DELAY );
    	{
    		for( ulIndex = 0U; ulIndex < SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS; ulIndex++ )
    		{
    			if( pxStore->subscriptionList[ ulIndex ].usFilterStringLength == usTopicFilterLength )
    			{
    				if( strncmp( pxStore->subscriptionList[ ulIndex ].pcSubscriptionFilterString, pcTopicFilterString, usTopicFilterLength ) == 0 )
    				{
    					memset( &( pxStore->subscriptionList[ ulIndex ] ), 0x00, sizeof( SubscriptionElement_t ) );
    				}
    			}
    		}
    	}
    	xSemaphoreGive( xGlobalSubscriptionStore.mutex );
    }
}

/*-----------------------------------------------------------*/

bool SubscriptionStore_HandlePublish( SubscriptionStore_t * pxStore,
                              MQTTPublishInfo_t * pxPublishInfo )
{
    uint32_t ulIndex = 0;
    bool isMatched = false, publishHandled = false;

    if( ( pxStore == NULL ) ||
        ( pxPublishInfo == NULL ) )
    {
        LogError( ( "Invalid parameter. pxStore=%p, pxPublishInfo=%p,",
        		    pxStore,
                    pxPublishInfo ) );
    }
    else
    {
    	xSemaphoreTake( xGlobalSubscriptionStore.mutex, portMAX_DELAY );
    	{
    		for( ulIndex = 0U; ulIndex < SUBSCRIPTION_MANAGER_MAX_SUBSCRIPTIONS; ulIndex++ )
    		{
    			if( pxStore->subscriptionList[ ulIndex ].usFilterStringLength > 0 )
    			{
    				MQTT_MatchTopic( pxPublishInfo->pTopicName,
    						pxPublishInfo->topicNameLength,
							pxStore->subscriptionList[ ulIndex ].pcSubscriptionFilterString,
							pxStore->subscriptionList[ ulIndex ].usFilterStringLength,
							&isMatched );

    				if( isMatched == true )
    				{
    					pxStore->subscriptionList[ ulIndex ].pxIncomingPublishCallback( pxStore->subscriptionList[ ulIndex ].pvIncomingPublishCallbackContext,
    							pxPublishInfo );
    					publishHandled = true;
    				}
    			}
    		}
    	}
    	xSemaphoreGive( xGlobalSubscriptionStore.mutex );
    }

    return publishHandled;
}

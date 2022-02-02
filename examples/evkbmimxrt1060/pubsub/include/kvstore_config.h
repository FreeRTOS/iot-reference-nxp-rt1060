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
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

#ifndef _KVSTORE_CONFIG_H
#define _KVSTORE_CONFIG_H

typedef enum KVStoreKey
{
    KVS_CORE_THING_NAME,
	KVS_CORE_MQTT_ENDPOINT,
	KVS_CORE_MQTT_PORT,
	KVS_NUM_KEYS
} KVStoreKey_t;

/* Define default values for common attributes */
#define THING_NAME_DFLT 				"NXP_RT_1060"
#define MQTT_ENDOPOINT_DFLT 			"a31zvyed820ljz-ats.iot.us-east-1.amazonaws.com"

#define KVSTORE_KEY_MAX_LEN		16
#define KVSTORE_VAL_MAX_LEN		256

#define KVSTORE_FILE_PATH ( "/kvstore")

/* Array to map between strings and KVStoreKey_t IDs */
#define KVSTORE_KEYS 	    \
{							\
	"THINGNAME",			\
	"ENDPOINT",		        \
	"PORT",			        \
}

#define KV_STORE_DEFAULTS \
{ \
	KV_DFLT( KV_TYPE_STRING, THING_NAME_DFLT 		), /* CS_CORE_THING_NAME */ 	\
	KV_DFLT( KV_TYPE_STRING, MQTT_ENDOPOINT_DFLT	), /* CS_CORE_MQTT_ENDPOINT */	\
	KV_DFLT( KV_TYPE_UINT32, 8883 					), /* CS_CORE_MQTT_PORT */		\
}

#endif /* _KVSTORE_CONFIG_H */

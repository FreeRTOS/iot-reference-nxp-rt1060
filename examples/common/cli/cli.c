/*
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 *
 * 1 tab == 4 spaces!
 */
#include <string.h>
#include "FreeRTOS.h"
#include "task.h"
#include "FreeRTOS_CLI_Console.h"
#include "FreeRTOS_CLI.h"
#include "kvstore.h"

#define MAX_COMMAND_BUFFER_LENGTH    ( 512 )

#define MAX_OUTPUT_BUFFER_LENGTH     ( 512 )

static BaseType_t prvConfigCommandHandler( char * pcWriteBuffer,
                                           size_t xWriteBufferLen,
                                           const char * pcCommandString );


static CLI_Command_Definition_t xCommandConfig =
{
    .pcCommand                   = "CONF",
    .pcHelpString                = "Device Configuration: CONF <KEY>=<VALUE> or CONF <KEY>?\n",
    .pxCommandInterpreter        = prvConfigCommandHandler,
    .cExpectedNumberOfParameters = 1
};

extern xConsoleIO_t uartConsoleIO;

static char commandBuffer[ MAX_COMMAND_BUFFER_LENGTH ];

static BaseType_t prvParseConfigCommand( const char * pcCommandString,
                                         size_t commandLength,
                                         KVStoreKey_t * pKeyType,
                                         char ** pValue,
                                         size_t * pValueLength,
                                         BaseType_t * pIsRead )
{
    BaseType_t parseResult = pdFAIL;
    size_t valueLength, commandIndex = 0;
    const char * pKeyFound = NULL;

    parseResult = KVStore_getKey( pcCommandString, commandLength, &pKeyFound, pKeyType );

    if( parseResult == pdPASS )
    {
        commandIndex += strlen( pKeyFound );

        if( commandIndex < commandLength )
        {
            if( pcCommandString[ commandIndex++ ] == '=' )
            {
                valueLength = commandLength - commandIndex;

                if( valueLength > 0 )
                {
                    ( *pIsRead ) = pdFALSE;
                    ( *pValue ) = ( pcCommandString + commandIndex );
                    ( *pValueLength ) = valueLength;
                    parseResult = pdPASS;
                }
                else
                {
                    parseResult = pdFAIL;
                }
            }
            else if( pcCommandString[ commandIndex ] == '?' )
            {
                ( *pIsRead ) = pdFALSE;
                parseResult = pdPASS;
            }
            else
            {
                parseResult = pdFAIL;
            }
        }
        else
        {
            parseResult = pdFAIL;
        }
    }

    return parseResult;
}

static BaseType_t prvConfigCommandHandler( char * pcWriteBuffer,
                                           size_t xWriteBufferLen,
                                           const char * pcCommandString )
{
    BaseType_t result = pdFAIL;
    const char * pParameter = NULL;
    char * pValue = NULL;
    size_t valueLength = 0;
    BaseType_t isRead = pdFALSE, paramLength = 0U;
    KVStoreKey_t kvStoreKey;

    pParameter = FreeRTOS_CLIGetParameter( pcCommandString, 1U, &paramLength );

    if( pParameter != NULL )
    {
        result = prvParseConfigCommand( pParameter, paramLength, &kvStoreKey, &pValue, &valueLength, &isRead );

        if( result == pdPASS )
        {
            if( isRead == pdFALSE )
            {
                result = KVStore_setString( kvStoreKey, valueLength, pValue );
            }
            else
            {
                valueLength = KVStore_getString( kvStoreKey, pcWriteBuffer, xWriteBufferLen );

                if( valueLength == 0 )
                {
                    result = pdFAIL;
                }
            }
        }
    }

    if( result == pdPASS )
    {
        strncpy( pcWriteBuffer, "COMMAND OK", xWriteBufferLen );
    }
    else
    {
        strncpy( pcWriteBuffer, "COMMAND NOK", xWriteBufferLen );
    }

    return pdTRUE;
}

void vCLITask( void * pvParam )
{
    BaseType_t xResult;

    xResult = FreeRTOS_CLIRegisterCommand( &xCommandConfig );
    configASSERT( xResult == pdTRUE );


    FreeRTOS_CLIEnterConsoleLoop( uartConsoleIO,
                                  commandBuffer,
                                  MAX_COMMAND_BUFFER_LENGTH,
                                  FreeRTOS_CLIGetOutputBuffer(),
                                  configCOMMAND_INT_MAX_OUTPUT_SIZE );


    vTaskDelete( NULL );
}

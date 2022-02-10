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
#include "FreeRTOS.h"
#include "FreeRTOS_CLI_Console.h"
#include "fsl_debug_console.h"


int32_t uart_read( char * const pcInputBuffer,
                   uint32_t xInputBufferLen );

void uart_write( const char * const pcOutputBuffer,
                 uint32_t xOutputBufferLen );

xConsoleIO_t uartConsoleIO =
{
    .read  = uart_read,
    .write = uart_write
};

int32_t uart_read( char * const pcInputBuffer,
                   uint32_t xInputBufferLen )
{
    int charRead;

    /*
     * Read one character at a time from Debug console waiting if necessary for any characters
     * to be entered.
     */
    charRead = DbgConsole_Getchar();


    pcInputBuffer[ 0 ] = charRead;

    return 1U;
}

void uart_write( const char * const pcOutputBuffer,
                 uint32_t xOutputBufferLen )
{
    int32_t status;
    uint32_t index;

    if( xOutputBufferLen > 0 )
    {
        for( index = 0; index < xOutputBufferLen; index++ )
        {
            /*configPRINTF(( "%.*s", xOutputBufferLen, pcOutputBuffer )); */

            status = DbgConsole_Putchar( pcOutputBuffer[ index ] );

            if( status < 0 )
            {
                break;
            }
        }

        ( void ) DbgConsole_Flush();
    }
}

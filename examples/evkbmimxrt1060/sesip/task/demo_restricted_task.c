/*
 * FreeRTOS version 202012.00-LTS
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
 *
 * 1 tab == 4 spaces!
 */

/**
 * @brief Demonstration of Memory Protection Unit functionalities.
 * Demo creates two restricted tasks read-only task and and a read write task.
 * To find more about create restricted task API, see: https://www.freertos.org/xTaskCreateRestricted.html.
 * Read-only task has read only access to a shared memory region, while Read-Write task has both read and write
 * access to it. Read-only task sets a global flag to one and then try to write to the shared memory region, which generates
 * hard fault by MPU. The hard fault handler implemented in this demo handles the exception gracefully by setting the global
 * flag back to zero and skipping to the next instruction in the task. The read only task verifies that flag is reset to zero to confirm
 * that the memory fault was raised and handled gracefully.
 */

/* FreeRTOS include. */
#include "FreeRTOS.h"

/* Task API include. */
#include "task.h"

/* Contains PRINTF APIs. */
#include "fsl_debug_console.h"

/**
 * @brief Flag to enable or disable memory fault injection.
 * To enable, set the flag to 1. Enabling this will cause the read-only task to write to a shared memory region
 * thereby causing a hard fault.
 */
#define INJECT_TEST_MEMORY_FAULT      ( 0 )

/**
 * @brief Size of the shared memory between the restricted tasks.
 */
#define SHARED_MEMORY_SIZE            32

/**
 * @brief Size of the memory region used by the Read only task and hard fault handler.
 */
#define MIN_REGION_SIZE               32

/**
 * @brief Stack size of the restricted tasks.
 */
#define RESTRICTED_TASK_STACK_SIZE    128

/*
 * @brief Macro to override printf funtion to run it in privileged mode.
 * NXP PRINTF code resides somewhere in RAM that could be provided as accessible region, but it's simpler to
 * just run it as privileged */
#define MPU_PRINTF( ... )                                      \
    {                                                          \
        BaseType_t xRunningPrivileged = xPortRaisePrivilege(); \
        PRINTF( __VA_ARGS__ );                                 \
        vPortResetPrivilege( xRunningPrivileged );             \
    }


/* For readability. Read about Hardfault Entry in ARMv7 docs for more details */
typedef struct
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uint32_t lr;
    uint32_t return_address;
    uint32_t xPSR;
} HardFaultStack_t;


/**
 * @brief Calls the port specific code to raise the privilege.
 *
 * @return pdFALSE if privilege was raised, pdTRUE otherwise.
 */
extern BaseType_t xPortRaisePrivilege( void );

/**
 * @brief Calls the port specific code to reset the privilege.
 * If xRunningPrivileged is pdFALSE, calls the port specific
 * code to reset the privilege, otherwise does nothing.
 *
 * @param[in] xRunningPrivileged Whether running in privelged mode or not.
 */
extern void vPortResetPrivilege( BaseType_t xRunningPrivileged );

/**
 * @brief Function used to dump the MPU memory regions allocated by linker script.
 */
void printRegions( void );

/**
 * @brief The Read write restricted task.
 * Task loops and keeps writing to the shared memory region. Since task has both read and write access it should
 * not cause a memory fault.
 *
 * @param[in] pvParameters Parameters to the task.
 */
static void prvRWAccessTask( void * pvParameters );

/**
 * @brief The read only task
 * Task loops and reads from the shared memory region. If INJECT_TEST_MEMORY_FAULT is set to 1, task also writes to
 * shared memory region. Using hard fault handler it recovers from the hard fault and prints the memory access violation
 * to the console.
 *
 * @param[in] pvParameters Parameters to the task.
 */
static void prvROAccessTask( void * pvParameters );

/**
 * @brief Memory regions used by the linker script.
 */
extern uint32_t __privileged_functions_start__[];
extern uint32_t __privileged_functions_end__[];
extern uint32_t __FLASH_segment_start__[];
extern uint32_t __FLASH_segment_end__[];
extern uint32_t __privileged_data_start__[];
extern uint32_t __privileged_data_end__[];
extern uint32_t __syscalls_flash_start__[];
extern uint32_t __syscalls_flash_end__[];
extern uint32_t __SRAM_segment_start__[];
extern uint32_t __SRAM_segment_end__[];


/**
 * @brief Shared memory area used between the restricted tasks.
 */
static uint8_t ucSharedMemory[ SHARED_MEMORY_SIZE ] __attribute__( ( aligned( SHARED_MEMORY_SIZE ) ) );

/**
 * @brief Statically allocated stack for Read-write access restristed task.
 */
static StackType_t xRWAccessTaskStack[ RESTRICTED_TASK_STACK_SIZE ] __attribute__( ( aligned( RESTRICTED_TASK_STACK_SIZE * sizeof( StackType_t ) ) ) );

/*
 * @brief The memory region shared between Read only task and hard fault handler.
 *
 * This is how RO task communicates to handler that it intentionally memory faulted.
 * Note, handlers run priviliged thus will have access)
 * Also note, 32B is minimum valid size for region*/
static volatile uint8_t ucROTaskFaultTracker[ MIN_REGION_SIZE ] __attribute__( ( aligned( MIN_REGION_SIZE ) ) ) = { 0 };

/**
 * @brief Statically allocated stack for Read-only access restristed task.
 */
static StackType_t xROAccessTaskStack[ RESTRICTED_TASK_STACK_SIZE ] __attribute__( ( aligned( RESTRICTED_TASK_STACK_SIZE * sizeof( StackType_t ) ) ) );

/* ------------------------------------------------------------------------------- */

void printRegions( void )
{
    uint32_t * tmp = NULL;

    tmp = __privileged_functions_start__;
    tmp = __privileged_functions_end__;
    tmp = __FLASH_segment_start__;
    tmp = __FLASH_segment_end__;
    tmp = __privileged_data_start__;
    tmp = __privileged_data_end__;

    ( void ) tmp;

    PRINTF( "\r\n" );
    PRINTF( "privileged functions: %08x - %08x\r\n", __privileged_functions_start__, __privileged_functions_end__ );
    PRINTF( "privileged data:      %08x - %08x\r\n", __privileged_data_start__, __privileged_data_end__ );
    PRINTF( "system calls:         %08x - %08x\r\n", __syscalls_flash_start__, __syscalls_flash_end__ );
    PRINTF( "flash segment:        %08x - %08x\r\n", __FLASH_segment_start__, __FLASH_segment_end__ );
    PRINTF( "sram segment:         %08x - %08x\r\n", __SRAM_segment_start__, __SRAM_segment_end__ );
    PRINTF( "\r\n" );
}

static void prvRWAccessTask( void * pvParameters )
{
    /* Unused parameters. */
    ( void ) pvParameters;

    ucSharedMemory[ 0 ] = 0;

    while( 1 )
    {
        ucSharedMemory[ 0 ] = 1;
        MPU_PRINTF( "Ran RW task\r\n" );

        vTaskDelay( pdMS_TO_TICKS( 8000 ) );
    }
}

static void prvROAccessTask( void * pvParameters )
{
    uint8_t ucVal;

    /* Unused parameters. */
    ( void ) pvParameters;
    ucROTaskFaultTracker[ 0 ] = 0;

    for( ; ; )
    {
        /* This task has RO access to ucSharedMemory and therefore it can read
         * it but cannot modify it. */
        ucVal = ucSharedMemory[ 0 ];

        /* Silent compiler warnings about unused variables. */
        ( void ) ucVal;

        #if ( INJECT_TEST_MEMORY_FAULT == 1 )
            ucROTaskFaultTracker[ 0 ] = 1;

            MPU_PRINTF( "Triggering memory violation...\r\n" );

            /* Illegal access to generate Memory Fault. */
            ucSharedMemory[ 0 ] = 0;

            /* Ensure that the above line did generate MemFault and the fault
             * handler did clear the  ucROTaskFaultTracker[ 0 ]. */
            if( ucROTaskFaultTracker[ 0 ] == 0 )
            {
                MPU_PRINTF( "Access Violation handled.\r\n" );
            }
            else
            {
                MPU_PRINTF( "Error: Access violation should have triggered a fault\r\n" );
            }
        #endif /* ifdef INJECT_TEST_MEMORY_FAULT */
        MPU_PRINTF( "Ran RO task\r\n" );

        vTaskDelay( pdMS_TO_TICKS( 5000 ) );
    }
}

void xCreateRestrictedTasks( BaseType_t xPriority )
{
    /* Create restricted tasks */
    TaskParameters_t xRWAccessTaskParameters =
    {
        .pvTaskCode     = prvRWAccessTask,
        .pcName         = "RWAccess",
        .usStackDepth   = RESTRICTED_TASK_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = xPriority,
        .puxStackBuffer = xRWAccessTaskStack,
        .xRegions       =
        {
            { ucSharedMemory, SHARED_MEMORY_SIZE, portMPU_REGION_READ_WRITE | portMPU_REGION_EXECUTE_NEVER },
            { 0,              0,                  0                                                        },
            { 0,              0,                  0                                                        },
        }
    };

    xTaskCreateRestricted( &( xRWAccessTaskParameters ), NULL );

    TaskParameters_t xROAccessTaskParameters =
    {
        .pvTaskCode     = prvROAccessTask,
        .pcName         = "ROAccess",
        .usStackDepth   = RESTRICTED_TASK_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = xPriority,
        .puxStackBuffer = xROAccessTaskStack,
        .xRegions       =
        {
            { ucSharedMemory,                  SHARED_MEMORY_SIZE, portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY | portMPU_REGION_EXECUTE_NEVER },
            { ( void * ) ucROTaskFaultTracker, SHARED_MEMORY_SIZE, portMPU_REGION_READ_WRITE | portMPU_REGION_EXECUTE_NEVER                             },
            { 0,                               0,                  0                                                                                    }
            /*{ 0x20000500, 0x100, portMPU_REGION_READ_WRITE }, */
        }
    };
    xTaskCreateRestricted( &( xROAccessTaskParameters ), NULL );
}


/* ------------------------------------------------------------------------------- */

/**
 * @brief The hard fault handler defined by the demo.
 * Function takes in hardfaulted stack address, finds out the next instructions to skip to,
 * resets the shared flag to zero for read-only task and then skips the stack pointer to the next
 * instruction to be executed.
 */
portDONT_DISCARD void vHandleMemoryFault( uint32_t * pulFaultStackAddress )
{
    uint32_t ulPC;
    uint16_t usOffendingInstruction;

    HardFaultStack_t * const xFaultStack = ( HardFaultStack_t * ) pulFaultStackAddress;

    /* Read program counter. */
    ulPC = xFaultStack->return_address;

    if( ucROTaskFaultTracker[ 0 ] == 1 )
    {
        /* Read the offending instruction. */
        usOffendingInstruction = *( uint16_t * ) ulPC;

        /* From ARM docs:
         * If the value of bits[15:11] of the halfword being decoded is one of
         * the following, the halfword is the first halfword of a 32-bit
         * instruction:
         * - 0b11101.
         * - 0b11110.
         * - 0b11111.
         * Otherwise, the halfword is a 16-bit instruction.
         */

        /* Extract bits[15:11] of the offending instruction. */
        usOffendingInstruction = usOffendingInstruction & 0xF800;
        usOffendingInstruction = ( usOffendingInstruction >> 11 );

        /* Increment to next instruction, depending on current instruction size (32-bit or 16-bit) */
        if( ( usOffendingInstruction == 0x001F ) ||
            ( usOffendingInstruction == 0x001E ) ||
            ( usOffendingInstruction == 0x001D ) )
        {
            ulPC += 4;
        }
        else
        {
            ulPC += 2;
        }

        /* Indicate to RO task its expected fault was handled */
        ucROTaskFaultTracker[ 0 ] = 0;

        /* Resume execution after offending instruction from RO task */
        xFaultStack->return_address = ulPC;

        PRINTF( "Expected memory violation caught by handler...\r\n", ulPC );
    }
    else
    {
        PRINTF( "Memory Access Violation. Inst @ %x\r\n", ulPC );

        while( 1 )
        {
        }
    }
}

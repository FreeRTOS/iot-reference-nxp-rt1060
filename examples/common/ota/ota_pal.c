/*
 * FreeRTOS OTA PAL V1.0.0
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* OTA PAL implementation for NXP MCUXpresso SDK. */

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "ota_config.h"
#include "ota_pal.h"
#include "fsl_common.h"
#include "mflash_drv.h"

#include "mcuboot_app_support.h"


/* PAL file context structure */
typedef struct
{
    const AfrOtaJobDocumentFields_t * FileXRef;
    uint32_t partition_log_addr;
    uint32_t partition_phys_addr;
    uint32_t partition_size;
    uint32_t next_erase_addr;
    uint32_t file_size;
    uint32_t page_size;
} PAL_FileContext_t;

static PAL_FileContext_t prvPAL_CurrentFileContext;

OtaPalStatus_t xFlashPalValidateSignature( uint8_t * pMappedAddress,
                                           size_t mappedLength,
                                           char * pCertificatePath,
                                           size_t certlength,
                                           uint8_t * pSignature,
                                           size_t signatureLength );


static PAL_FileContext_t * prvPAL_GetPALFileContext( AfrOtaJobDocumentFields_t * const pFileContext )
{
    if( pFileContext == NULL )
    {
        return NULL;
    }
    else if( prvPAL_CurrentFileContext.FileXRef != pFileContext )
    {
        return NULL;
    }
    else
    {
        return &prvPAL_CurrentFileContext;
    }
}


OtaPalStatus_t otaPal_Abort( AfrOtaJobDocumentFields_t * const pFileContext )
{
    OtaPalStatus_t result = OtaPalSuccess;

    LogInfo( ( "[OTA-NXP] Abort" ) );

    pFileContext->fileId = 0;
    pFileContext->filepath = NULL;
    return result;
}


OtaPalJobDocProcessingResult_t otaPal_CreateFileForRx( AfrOtaJobDocumentFields_t * const pFileContext )
{
    partition_t update_partition;
    PAL_FileContext_t * PalFileContext = &prvPAL_CurrentFileContext;

    LogDebug( ( "[OTA-NXP] CreateFileForRx" ) );

    if( otaPal_SetPlatformImageState( pFileContext, OtaImageStateAccepted ) == OtaPalSuccess )
    {
        /* TODO: Check here if anything is to be verified before sending the
         * success message to IoT core. */
        return OtaPalNewImageBooted;
    }

    if( bl_get_update_partition_info( &update_partition ) != kStatus_Success )
    {
        LogError( ( "[OTA-NXP] Could not get update partition information" ) );
        return OtaPalRxFileCreateFailed;
    }

    /* Keep partition info in the file context */
    PalFileContext->partition_log_addr = update_partition.start;
    PalFileContext->partition_size = update_partition.size;

    /* Obtain physical address to perform flash operations with */
    PalFileContext->partition_phys_addr = mflash_drv_log2phys( ( void * ) update_partition.start, update_partition.size );

    if( PalFileContext->partition_phys_addr == MFLASH_INVALID_ADDRESS )
    {
        LogError( ( "[OTA-NXP] Could not get update partition FLASH address" ) );
        return OtaPalRxFileCreateFailed;
    }

    /* Check partition alignment */
    if( !mflash_drv_is_sector_aligned( PalFileContext->partition_phys_addr ) || !mflash_drv_is_sector_aligned( PalFileContext->partition_size ) )
    {
        LogError( ( "[OTA-NXP] Invalid update partition" ) );
        return OtaPalRxFileCreateFailed;
    }

    /* Check whether the file fits at all */
    if( pFileContext->fileSize > update_partition.size )
    {
        LogError( ( "[OTA-NXP] File too large" ) );
        return OtaPalRxFileTooLarge;
    }

    /* Actual size of the file according to data received */
    PalFileContext->file_size = 0;

    /* Allocate buffer to keep data for the page containing image header until the rest of the image is received */
    PalFileContext->page_size = MFLASH_PAGE_SIZE;

    /* Pre-set address of area not erased so far */
    PalFileContext->next_erase_addr = PalFileContext->partition_phys_addr;

    PalFileContext->FileXRef = pFileContext; /* pointer cross reference for integrity check */

    /*C->pFile = ( uint8_t * ) PalFileContext; */

    return OtaPalSuccess;
}


OtaPalStatus_t otaPal_CloseFile( AfrOtaJobDocumentFields_t * const pFileContext )
{
    OtaPalStatus_t result = OtaPalSuccess;
    PAL_FileContext_t * PalFileContext;
    uint8_t * file_data = NULL;

    LogDebug( ( "[OTA-NXP] CloseFile" ) );

    PalFileContext = prvPAL_GetPALFileContext( pFileContext );

    if( PalFileContext == NULL )
    {
        return OtaPalFileClose;
    }

    if( PalFileContext->file_size != pFileContext->fileSize )
    {
        LogWarn( ( "[OTA-NXP] Actual file size is not as expected" ) );
    }

    file_data = mflash_drv_phys2log( PalFileContext->partition_phys_addr, PalFileContext->file_size );

    if( file_data == NULL )
    {
        return OtaPalSignatureCheckFailed;
    }

    result = xFlashPalValidateSignature( ( void * ) file_data,
                                         PalFileContext->file_size,
                                         ( char * ) pFileContext->certfile,
                                         pFileContext->certfileLen,
                                         pFileContext->signature,
                                         pFileContext->signatureLen );

    if( result != OtaPalSuccess )
    {
        LogError( ( "[OTA-NXP] CheckFileSignature failed" ) );
    }

#ifndef DISABLE_OTA_CLOSE_FILE_HEADER_CHECK
    /* Sanity check of the image and its header solely from the flash as the bootloader would do */
    if( result == OtaPalSuccess )
    {
        if( bl_verify_image( file_data, PalFileContext->file_size ) <= 0 )
        {
            LogError( ( "[OTA-NXP] Invalid image" ) );
            result = OtaPalBootInfoCreateFailed;
        }
    }

    /* Prepare image to be booted in test mode */
    if( ( result == OtaPalSuccess ) && ( bl_update_image_state( kSwapType_ReadyForTest ) != kStatus_Success ) )
    {
        LogError( ( "[OTA-NXP] Failed to set image state" ) );
        result = OtaPalBootInfoCreateFailed;
    }
#endif /* ifndef DISABLE_OTA_CLOSE_FILE_HEADER_CHECK */

    pFileContext->fileId = 0;
    return result;
}


int16_t otaPal_WriteBlock( AfrOtaJobDocumentFields_t * const pFileContext,
                           uint32_t ulOffset,
                           uint8_t * const pcData,
                           uint32_t ulBlockSize )
{
    int16_t retval = 0;
    int32_t mflash_result = 0;

    uint8_t * data;
    uint32_t data_offset;
    uint32_t data_remaining;

    PAL_FileContext_t * PalFileContext;

    LogDebug( ( "[OTA-NXP] WriteBlock 0x%x : 0x%x", ulOffset, ulBlockSize ) );

    PalFileContext = prvPAL_GetPALFileContext( pFileContext );

    if( PalFileContext == NULL )
    {
        return -1;
    }

    /* Check for possible partition boundary overrun */
    if( ulOffset + ulBlockSize > PalFileContext->partition_size )
    {
        return -1;
    }

    /*
     * The block is expected to be page aligned. The otaconfigLOG2_FILE_BLOCK_SIZE should be set so that the blocks are at least of page size (or larger).
     * That way all blocks except for the last one would be block aligned in both offset and size
     */
    if( !mflash_drv_is_page_aligned( ulOffset ) )
    {
        LogError( ( "[OTA-NXP] Block is not page aligned" ) );
        return -1;
    }

    data = pcData;
    data_offset = ulOffset;
    data_remaining = ulBlockSize;

    /* The block may span multiple pages, process in a loop */
    while( data_remaining )
    {
        uint32_t len = data_remaining < PalFileContext->page_size ? data_remaining : PalFileContext->page_size;

        /* Perform erase when encountering next sector */
        while( PalFileContext->partition_phys_addr + data_offset >= PalFileContext->next_erase_addr )
        {
            LogDebug( ( "[OTA-NXP] Erasing sector 0x%x", PalFileContext->next_erase_addr ) );
            mflash_result = mflash_drv_sector_erase( PalFileContext->next_erase_addr );

            if( mflash_result != 0 )
            {
                break;
            }

            PalFileContext->next_erase_addr += MFLASH_SECTOR_SIZE;
        }

        if( mflash_result != 0 )
        {
            retval = -1;
            break;
        }

        if( ( len == PalFileContext->page_size ) && ( ( ( uint32_t ) data % 4 ) == 0 ) )
        {
            mflash_result = mflash_drv_page_program( PalFileContext->partition_phys_addr + data_offset, ( void * ) data );
        }
        else
        {
            /* Data size not aligned to page size, use temporary buffer */
            uint32_t * page_buffer = pvPortMalloc( PalFileContext->page_size );

            if( page_buffer == NULL )
            {
                LogError( ( "[OTA-NXP] Could not allocate page buffer" ) );
                retval = -1;
                break;
            }

            memset( page_buffer, 0xff, PalFileContext->page_size );
            memcpy( page_buffer, data, len );
            mflash_result = mflash_drv_page_program( PalFileContext->partition_phys_addr + data_offset, page_buffer );
            vPortFree( page_buffer );
        }

        if( mflash_result != 0 )
        {
            retval = -1;
            break;
        }

        data += len;
        data_offset += len;
        data_remaining -= len;
        retval += len;
    }

    /* Update size of file received so far */
    if( ( retval > 0 ) && ( PalFileContext->file_size < data_offset ) )
    {
        PalFileContext->file_size = data_offset;
    }

    return retval;
}


OtaPalStatus_t otaPal_ActivateNewImage( AfrOtaJobDocumentFields_t * const pFileContext )
{
    LogInfo( ( "[OTA-NXP] ActivateNewImage" ) );

    otaPal_ResetDevice( pFileContext ); /* go for reboot */
    return OtaPalSuccess;
}


OtaPalStatus_t otaPal_SetPlatformImageState( AfrOtaJobDocumentFields_t * const pFileContext,
                                             OtaImageState_t eState )
{
    OtaPalStatus_t result = OtaPalSuccess;

    LogDebug( ( "[OTA-NXP] SetPlatformImageState %d", eState ) );

    if( otaPal_GetPlatformImageState( pFileContext ) == OtaPalImageStatePendingCommit )
    {
        /* Device in test mode */
        switch( eState )
        {
            case OtaImageStateAccepted:

                /* Request the bootloader to switch the image permanently */
                if( bl_update_image_state( kSwapType_Permanent ) != kStatus_Success )
                {
                    /* Override result code by a state specific one */
                    result = OtaPalCommitFailed;
                }

                break;

            case OtaImageStateRejected:

                /* Invalidate the image */
                if( bl_update_image_state( kSwapType_Fail ) != kStatus_Success )
                {
                    /* Override result code by a state specific one */
                    result = OtaPalRejectFailed;
                }

                break;

            case OtaImageStateAborted:

                /* Invalidate the image */
                if( bl_update_image_state( kSwapType_Fail ) != kStatus_Success )
                {
                    /* Override result code by a state specific one */
                    result = OtaPalAbortFailed;
                }

                break;

            case OtaImageStateTesting:
                result = OtaPalSuccess;
                break;

            default:
                result = OtaPalBadImageState;
                break;
        }
    }
    else
    {
        /* Normal mode */
        switch( eState )
        {
            case OtaImageStateAccepted:
                /* No pending commit */
                result = OtaPalCommitFailed;
                break;

            case OtaImageStateRejected:
                result = OtaPalRejectFailed;
                break;

            case OtaImageStateAborted:
                result = OtaPalAbortFailed;
                break;

            case OtaImageStateTesting:
                result = OtaPalBadImageState;
                break;

            default:
                result = OtaPalBadImageState;
                break;
        }
    }

    return result;
}


OtaPalImageState_t otaPal_GetPlatformImageState( AfrOtaJobDocumentFields_t * const pFileContext )
{
    uint32_t state;

    if( bl_get_image_state( &state ) != kStatus_Success )
    {
        return OtaPalImageStateInvalid;
    }

    switch( state )
    {
        case kSwapType_ReadyForTest:
            return OtaPalImageStateValid;

            break;

        case kSwapType_Testing:
            return OtaPalImageStatePendingCommit;

            break;
    }

    return OtaPalImageStateInvalid;
}


OtaPalStatus_t otaPal_ResetDevice( AfrOtaJobDocumentFields_t * const pFileContext )
{
    LogInfo( ( "[OTA-NXP] SystemReset" ) );
    vTaskDelay( 100 / portTICK_PERIOD_MS );
    NVIC_SystemReset(); /* this should never return */
}

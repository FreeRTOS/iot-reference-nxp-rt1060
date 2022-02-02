/*
 * FreeRTOS OTA PAL V1.0.0
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.
 * Copyright 2021 NXP
 * All Rights Reserved.
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

/* OTA PAL implementation for NXP RT1xxx. */

#include <string.h>

#include "ota.h"
#include "ota_pal.h"

#include "flash_info.h"
#include "mflash_drv.h"

#include "sbl_ota_flag.h"

#include "flexspi_nor_flash_ops.h"

#if defined(CONFIG_BOOT_ENCRYPTED_XIP)
#include "update_key_context.h"
#endif

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[OTA_FILE_SIG_KEY_STR_MAX_LENGTH] = "sig-sha256-ecdsa";

/* low level file context structure */
typedef struct
{
    const OtaFileContext_t *FileXRef;
    uint32_t Addr;
    uint32_t Size;
    uint32_t MaxSize;
} LL_FileContext_t;

static LL_FileContext_t prvPAL_CurrentFileContext;

static LL_FileContext_t *prvPAL_GetLLFileContext(OtaFileContext_t *const C)
{
    LL_FileContext_t *FileContext;

    if ((C == NULL) || (C->pFile == NULL))
    {
        return NULL;
    }

    FileContext = (LL_FileContext_t *)C->pFile;

    if ((FileContext == NULL) || (FileContext->FileXRef != C))
    {
        return NULL;
    }

    return FileContext;
}

OtaPalStatus_t xOtaPalAbort( OtaFileContext_t * const pFileContext )
{
    LogDebug("[OTA-NXP] Abort\r\n");

    pFileContext->pFile = NULL;
    return OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0U );
}


OtaPalStatus_t xOtaPalCreateFileForRx( OtaFileContext_t * const pOTAFileContext )
{
    LL_FileContext_t *FileContext = &prvPAL_CurrentFileContext;

    LogDebug("[OTA-NXP] CreateFileForRx\r\n");

    /* update partition address in FLASH memory and its size */
#ifdef SOC_REMAP_ENABLE
    uint8_t image_position;
    sfw_flash_read_ipc(REMAP_FLAG_ADDRESS, &image_position, 1);
    OTA_LOG_L1("[OTA-NXP] image_position= %d\r\n", image_position);
    if(image_position == 0x01)
    {
        if (pOTAFileContext->fileSize > FLASH_AREA_IMAGE_2_SIZE)
        {
            return OTA_PAL_COMBINE_ERR( OtaPalRxFileTooLarge, 0U );
        }
        FileContext->Addr = FLASH_AREA_IMAGE_2_OFFSET;
        FileContext->MaxSize = FLASH_AREA_IMAGE_2_SIZE;
    }
    else if(image_position == 0x02)
    {
        if (pOTAFileContext->fileSize > FLASH_AREA_IMAGE_1_SIZE)
        {
            return OTA_PAL_COMBINE_ERR( OtaPalRxFileTooLarge, 0U );
        }
        FileContext->Addr = FLASH_AREA_IMAGE_1_OFFSET;
        FileContext->MaxSize = FLASH_AREA_IMAGE_1_SIZE;
    }
    else
    {
        return kStatus_Fail;
    }
#else
    if (pOTAFileContext->fileSize > FLASH_AREA_IMAGE_2_SIZE)
    {
        return OTA_PAL_COMBINE_ERR( OtaPalRxFileTooLarge, 0U );
    }
    FileContext->Addr = FLASH_AREA_IMAGE_2_OFFSET;
    FileContext->MaxSize = FLASH_AREA_IMAGE_2_SIZE;
#endif

    LogDebug("[OTA-NXP] File_Addr = 0x%08x, File_Size = 0x%08x\r\n", FileContext->Addr, FileContext->MaxSize);

    /* actual size of the file according to data received */
    FileContext->Size     = 0;

    FileContext->FileXRef = pOTAFileContext; /* pointer cross reference for integrity check */
    pOTAFileContext->pFile = (uint8_t *)FileContext;

    return OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0U );
}


OtaPalStatus_t xOtaPalCloseFile( OtaFileContext_t * const pOTAContext )
{
    OtaPalStatus_t result = OtaPalSuccess;
    LL_FileContext_t *FileContext;
#ifdef SOC_REMAP_ENABLE
#ifdef SOC_IMXRT1170_SERIES
    uint32_t remap_offset = (*(uint32_t *)0x400CC428) & 0xFFFFF000;
#else //RT1060, RT1064
    uint32_t remap_offset = IOMUXC_GPR->GPR32 & 0xFFFFF000;
#endif
    uint8_t image_position;
#endif

#ifdef MCUBOOT_IMAGE
    struct image_version *cur_ver;
    struct image_version *new_ver;
    uint8_t cur_version[8];
    uint8_t new_version[8];
    int8_t cmp_result;
#endif

    LogDebug("[OTA-NXP] CloseFile\r\n");

    FileContext = prvPAL_GetLLFileContext(pOTAContext);
    if (FileContext == NULL)
    {
        return OTA_PAL_COMBINE_ERR( OtaPalFileClose, 0U );
    }

#ifdef SOC_REMAP_ENABLE
    //should disable remap when check signature.
    if (remap_offset != 0)
    {
        SBL_DisableRemap();
    }
#endif

    result = xFlashPalValidateSignature( ( void * ) (FileContext->Addr + MFLASH_BASE_ADDRESS ),
                                         FileContext->Size,
                                         pOTAContext->pCertFilepath,
                                         pOTAContext->pSignature->data,
                                         pOTAContext->pSignature->size );
    if (result != OtaPalSuccess)
    {
        LogDebug("[OTA-NXP] CheckFileSignature failed\r\n");
        return OTA_PAL_COMBINE_ERR( result, 0U );
    }

#ifdef MCUBOOT_IMAGE

#ifdef SOC_REMAP_ENABLE
    sfw_flash_read_ipc(REMAP_FLAG_ADDRESS, &image_position, 1);
    LogDebug("[prvPAL_CloseFile] image_position= %d\r\n", image_position);
    if(image_position == 0x01)
    {
        sfw_flash_read_ipc(FLASH_AREA_IMAGE_1_OFFSET + IMAGE_VERSION_OFFSET, cur_version, 8);
        cur_ver = (struct image_version *)cur_version;
        sfw_flash_read_ipc(FLASH_AREA_IMAGE_2_OFFSET + IMAGE_VERSION_OFFSET, new_version, 8);
        new_ver = (struct image_version *)new_version;
    }
    else if(image_position == 0x02)
    {
        //after check, enable remap
        SBL_EnableRemap(BOOT_FLASH_ACT_APP, BOOT_FLASH_ACT_APP+FLASH_AREA_IMAGE_1_SIZE, FLASH_AREA_IMAGE_1_SIZE);
        sfw_flash_read_ipc(FLASH_AREA_IMAGE_2_OFFSET + IMAGE_VERSION_OFFSET, cur_version, 8);
        cur_ver = (struct image_version *)cur_version;
        sfw_flash_read_ipc(FLASH_AREA_IMAGE_1_OFFSET + IMAGE_VERSION_OFFSET, new_version, 8);
        new_ver = (struct image_version *)new_version;
    }
    else
    {
        return OTA_PAL_COMBINE_ERR( OtaPalFileClose, 0U );
    }
#else
    sfw_flash_read(FLASH_AREA_IMAGE_1_OFFSET + IMAGE_VERSION_OFFSET, cur_version, 8);
    cur_ver = (struct image_version *)cur_version;
    sfw_flash_read(FLASH_AREA_IMAGE_2_OFFSET + IMAGE_VERSION_OFFSET, new_version, 8);
    new_ver = (struct image_version *)new_version;
#endif

    //check image version
    cmp_result = compare_image_version(new_ver, cur_ver);
    LogDebug("[OTA-NXP] cmp_result=%d\r\n", cmp_result);
    if(cmp_result > 0)
    {
        OTA_LOG_L1("[OTA-NXP] new image verison: %d.%d.%d\r\n", new_ver->iv_major, new_ver->iv_minor, new_ver->iv_revision);
    }
    else
    {
        OTA_LOG_L1("[OTA-NXP] The version number of the new image is not greater than the current image version number!\r\n");
        return OTA_PAL_COMBINE_ERR( OtaPalFileClose, 0U );
    }
#endif

    pOTAContext->pFile = NULL;
    return OTA_PAL_COMBINE_ERR( result, 0U );
}


int16_t xOtaPalWriteBlock( OtaFileContext_t * const pOTAFileContext,
                           uint32_t offset,
                           uint8_t * const pData,
                           uint32_t blockSize )
{
    int32_t result;
    LL_FileContext_t *FileContext;

    LogDebug("[OTA-NXP] WriteBlock %x : %x\r\n", offset, blockSize);

    FileContext = prvPAL_GetLLFileContext(pOTAFileContext);
    if (FileContext == NULL)
    {
        return -1;
    }

    if (offset + blockSize > FileContext->MaxSize)
    {
        return -1;
    }

    result = mflash_drv_write(FileContext->Addr + offset, pData, blockSize);
    if (result == 0)
    {
        /* zero indicates no error, return number of bytes written to the caller */
        result = blockSize;
        if (FileContext->Size < offset + blockSize)
        {
            /* extend file size according to highest offset */
            FileContext->Size = offset + blockSize;
        }
    }
    return result;
}


OtaPalStatus_t xOtaPalActivateNewImage( OtaFileContext_t * const pFileContext )
{
    LogDebug("[OTA-NXP] Write update type\r\n");
    write_update_type(UPDATE_TYPE_AWS_CLOUD);
    LogDebug("[OTA-NXP] Write image trailer\r\n");

    enable_image();
#if defined(CONFIG_BOOT_ENCRYPTED_XIP)
    update_key_context();
#endif
    LogDebug("[OTA-NXP] ActivateNewImage\r\n");

    /* go for reboot */
    return xOtaPalResetDevice( pFileContext );
}


OtaPalStatus_t xOtaPalResetDevice( OtaFileContext_t * const pFileContext )
{
    (void) pFileContext;
    LogDebug("[OTA-NXP] ResetDevice\r\n");

    NVIC_SystemReset(); /* this should never return */

    return OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, 0U );
}


OtaPalStatus_t xOtaPalSetPlatformImageState( OtaFileContext_t * const pFileContext,
                                             OtaImageState_t eState )
{
    OtaPalStatus_t result = OtaPalSuccess;
    uint8_t ota_type;

    LogDebug("[OTA-NXP] SetPlatformImageState %d\r\n", eState);

    if (xOtaPalGetPlatformImageState(pFileContext) == OtaPalImageStatePendingCommit)
    {
        /* Device in test mode */
        switch (eState)
        {
            case OtaImageStateAccepted:
                /* iamge is ok */
                sfw_flash_read(UPDATE_TYPE_FLAG_ADDRESS, &ota_type, 1);
                if (UPDATE_TYPE_AWS_CLOUD == ota_type)
                {
                    write_image_ok();
                }
                break;

            case OtaImageStateRejected:
                /* Invalidate the image */
                break;

            case OtaImageStateAborted:
                /* Invalidate the image */
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
        switch (eState)
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

    return OTA_PAL_COMBINE_ERR( result, 0U );
}


OtaPalImageState_t xOtaPalGetPlatformImageState( OtaFileContext_t * const pFileContext )
{
    uint8_t ota_status = 0;

    ( void ) pFileContext;

    LogDebug("[OTA-NXP] GetPlatformImageState\r\n");

    ota_status = read_ota_status();
    LogDebug("[OTA-NXP] ota_status = 0x%x\r\n", ota_status);

    if (ota_status == 0x00)
    {
        return OtaPalImageStateValid;
    }
    else if (ota_status == 0x01)
    {
        return OtaPalImageStatePendingCommit;
    }
    else
    {
        return OtaPalImageStateInvalid;
    }
}

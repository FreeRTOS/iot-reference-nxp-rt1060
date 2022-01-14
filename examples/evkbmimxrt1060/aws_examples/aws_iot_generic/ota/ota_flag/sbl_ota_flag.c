// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 */
#include "fsl_debug_console.h"
#include "flash_info.h"
#include "sbl_ota_flag.h"
#include <flexspi_nor_flash_ops.h>


const uint32_t boot_img_magic[] = {
    0xf395c277,
    0x7fefd260,
    0x0f505235,
    0x8079b62c,
};

void write_update_type(uint8_t type)
{
    uint8_t write_buf;
    status_t status;
    uint32_t primask;
    
    write_buf = type;

    PRINTF("write update type = 0x%x\r\n", write_buf);

    primask = DisableGlobalIRQ();    
    status = sfw_flash_write(UPDATE_TYPE_FLAG_ADDRESS, &write_buf, 1);
    if (status) 
    {
        PRINTF("write update type: failed to write current update type\r\n");
        return;
    }
    EnableGlobalIRQ(primask);
}

#ifdef MCUBOOT_IMAGE
void print_image_version(void)
{
    struct image_version *img_ver;
    uint8_t img_version[8];
    
    sfw_flash_read(FLASH_AREA_IMAGE_1_OFFSET + IMAGE_VERSION_OFFSET, img_version, 8);
    img_ver = (struct image_version *)img_version;
    
    PRINTF("Current image verison: %d.%d.%d\r\n", img_ver->iv_major, img_ver->iv_minor, img_ver->iv_revision);
}
#endif


#ifdef SOC_REMAP_ENABLE
struct remap_trailer s_remap_trailer;

uint8_t read_ota_status(void)
{
    struct remap_trailer remap_trailer;

    sfw_flash_read_ipc(REMAP_FLAG_ADDRESS, (uint8_t *)&remap_trailer, 32);

    if (remap_trailer.image_ok == 0xFF)
    {
        return 0x00;
    }
    else if (remap_trailer.image_ok == 0x04)
    {
        return 0x01;
    }
    else
    {
        return 0xFF;
    }    
}

/* write the remap image trailer */
void enable_image(void)
{
    uint32_t off;
    status_t status;
    uint32_t primask;

    memset((void *)&s_remap_trailer, 0xff, IMAGE_TRAILER_SIZE);
    memcpy((void *)s_remap_trailer.magic, boot_img_magic, sizeof(boot_img_magic));

    off = REMAP_FLAG_ADDRESS + 16;
    
    PRINTF("write magic number offset = 0x%x\r\n", off);

    primask = DisableGlobalIRQ();
    status = sfw_flash_write(off, (void *)&s_remap_trailer.magic, IMAGE_TRAILER_SIZE - 16);
    if (status) 
    {
        PRINTF("enable_image: failed to write remap flag\r\n");
        return;
    }
    EnableGlobalIRQ(primask);
}

void write_image_ok(void)
{
    uint32_t off;
    status_t status;
    uint32_t primask;
    
    sfw_flash_read(REMAP_FLAG_ADDRESS, &s_remap_trailer, 32);
    
    primask = DisableGlobalIRQ();
    status = sfw_flash_erase(FLASH_AREA_IMAGE_1_OFFSET - SECTOR_SIZE, SECTOR_SIZE);
    
    EnableGlobalIRQ(primask);
    
    memset((void *)s_remap_trailer.magic, 0xff, IMAGE_TRAILER_SIZE - 16);

    s_remap_trailer.image_ok = 0xFF;
    s_remap_trailer.pad1[3] = 0x0;
    
    off = REMAP_FLAG_ADDRESS;

    PRINTF("Write OK flag: off = 0x%x\r\n", off);
    
    primask = DisableGlobalIRQ();
    status = sfw_flash_write(off, (void *)&s_remap_trailer, IMAGE_TRAILER_SIZE);
    if (status) 
    {
        return;
    }
    EnableGlobalIRQ(primask);
}

void SBL_EnableRemap(uint32_t start_addr, uint32_t end_addr, uint32_t off)
{
    uint32_t * remap_start  = (uint32_t *)REMAPADDRSTART;
    uint32_t * remap_end    = (uint32_t *)REMAPADDREND;
    uint32_t * remap_offset = (uint32_t *)REMAPADDROFFSET;

#ifdef SOC_IMXRT1170_SERIES
    *remap_start = start_addr + 1;
#else
    *remap_start = start_addr;
#endif
    *remap_end = end_addr;
    *remap_offset = off;
}

void SBL_DisableRemap(void)
{
    uint32_t * remap_start  = (uint32_t *)REMAPADDRSTART;
    uint32_t * remap_end    = (uint32_t *)REMAPADDREND;
    uint32_t * remap_offset = (uint32_t *)REMAPADDROFFSET;

    *remap_start = 0;
    *remap_end = 0;
    *remap_offset = 0;
}

#else
uint8_t read_ota_status(void)
{
    uint32_t off;
    struct swap_trailer swap_trailer;

    off = FLASH_AREA_IMAGE_1_OFFSET + FLASH_AREA_IMAGE_1_SIZE - IMAGE_TRAILER_SIZE;
    
    sfw_flash_read(off, &swap_trailer, 32);

    if (swap_trailer.copy_done == 0xFF)
    {
        return 0x00;
    }
    else if (swap_trailer.copy_done == 0x01)
    {
        return 0x01;
    }
    else
    {
        return 0xFF;
    }      
}

struct swap_trailer s_swap_trailer;
/* write the image trailer at the end of the flash partition */
void enable_image(void)
{
    uint32_t off;
    status_t status;
    uint32_t primask;
#ifdef SOC_LPC55S69_SERIES
    /* The flash of LPC55xx have the limit of offset when do write operation*/
    uint8_t write_buff[512];
    memset(write_buff, 0xff, 512);
#endif    
    
    memset((void *)&s_swap_trailer, 0xff, IMAGE_TRAILER_SIZE);
    memcpy((void *)s_swap_trailer.magic, boot_img_magic, sizeof(boot_img_magic));

#ifdef SOC_LPC55S69_SERIES
    memcpy(&write_buff[512 - IMAGE_TRAILER_SIZE], (void *)&s_swap_trailer, IMAGE_TRAILER_SIZE);
    off = FLASH_AREA_IMAGE_2_OFFSET + FLASH_AREA_IMAGE_2_SIZE - 512;
#else
    off = FLASH_AREA_IMAGE_2_OFFSET + FLASH_AREA_IMAGE_2_SIZE - IMAGE_TRAILER_SIZE;
#endif

    PRINTF("write magic number offset = 0x%x\r\n", off);

    primask = DisableGlobalIRQ();
#ifdef SOC_LPC55S69_SERIES
    status = sfw_flash_write(off, write_buff, 512);
#else
    status = sfw_flash_write(off, (void *)&s_swap_trailer, IMAGE_TRAILER_SIZE);
#endif
    if (status) 
    {
        PRINTF("enable_image: failed to write trailer2\r\n");
        return;
    }
    EnableGlobalIRQ(primask);
}
void write_image_ok(void)
{
    uint32_t off;
    status_t status;
    uint32_t primask;
#ifdef SOC_LPC55S69_SERIES
    /* The flash of LPC55xx have the limit of offset when do write operation*/
    static uint8_t write_buff[512];
    memset(write_buff, 0xff, 512);
#endif    
    /* Erase update type flag */
    primask = DisableGlobalIRQ();
#if !defined(SOC_LPC55S69_SERIES)
    status = sfw_flash_erase(FLASH_AREA_IMAGE_1_OFFSET - SECTOR_SIZE, SECTOR_SIZE);
#endif
    
    EnableGlobalIRQ(primask);    

    memset((void *)&s_swap_trailer, 0xff, IMAGE_TRAILER_SIZE);
    memcpy((void *)s_swap_trailer.magic, boot_img_magic, sizeof(boot_img_magic));
    
    s_swap_trailer.image_ok= BOOT_FLAG_SET;

#ifdef SOC_LPC55S69_SERIES
    off = FLASH_AREA_IMAGE_1_OFFSET + FLASH_AREA_IMAGE_1_SIZE - 512;
    sfw_flash_read(off, write_buff, 512);
    memcpy(&write_buff[512 - IMAGE_TRAILER_SIZE], (void *)&s_swap_trailer, IMAGE_TRAILER_SIZE);
#else
    off = FLASH_AREA_IMAGE_1_OFFSET + FLASH_AREA_IMAGE_1_SIZE - IMAGE_TRAILER_SIZE;
#endif

    PRINTF("Write OK flag: off = 0x%x\r\n", off);
    
    primask = DisableGlobalIRQ();
#ifdef SOC_LPC55S69_SERIES
    sfw_flash_erase(off, 512);
    status = sfw_flash_write(off, write_buff, 512);
#else
    status = sfw_flash_erase(FLASH_AREA_IMAGE_2_OFFSET - SECTOR_SIZE, SECTOR_SIZE);
    status = sfw_flash_write(off, (void *)&s_swap_trailer, IMAGE_TRAILER_SIZE);
#endif
    if (status) 
    {
        return;
    }
    EnableGlobalIRQ(primask);
}
#endif

#ifdef MCUBOOT_IMAGE
/**
 * Compare image version numbers 
 *
 * @param version1           Pointer to the version number of first image.
 * @param version2           Pointer to the version number of second image.
 *
 * @retval -1           If version1 is strictly less than version2.
 * @retval 0            If the image version numbers are equal,
 *                      (not including the build number).
 * @retval 1            If version1 is strictly greater than version2.
 */
int8_t compare_image_version(const struct image_version *version1,
                 const struct image_version *version2)
{
    if (version1->iv_major > version2->iv_major) {
        return 1;
    }
    if (version1->iv_major < version2->iv_major) {
        return -1;
    }
    /* The major version numbers are equal, continue comparison. */
    if (version1->iv_minor > version2->iv_minor) {
        return 1;
    }
    if (version1->iv_minor < version2->iv_minor) {
        return -1;
    }
    /* The minor version numbers are equal, continue comparison. */
    if (version1->iv_revision > version2->iv_revision) {
        return 1;
    }
    if (version1->iv_revision < version2->iv_revision) {
        return -1;
    }

    return 0;
}
#endif

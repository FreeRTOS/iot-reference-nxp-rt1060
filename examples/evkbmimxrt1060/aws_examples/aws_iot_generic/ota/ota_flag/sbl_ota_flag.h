// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 */
 
#ifndef __SBL_OTA_FLAG_H__
#define __SBL_OTA_FLAG_H__


#define REMAP_FLAG_ADDRESS (FLASH_AREA_IMAGE_1_OFFSET - 32UL)
#define IMAGE_VERSION_OFFSET 0x14

#define BOOT_FLAG_SET       1

#define UPDATE_TYPE_FLAG_ADDRESS (FLASH_AREA_IMAGE_1_OFFSET - 28UL)

#define UPDATE_TYPE_SDCARD    0x01U
#define UPDATE_TYPE_UDISK     0x02U
#define UPDATE_TYPE_AWS_CLOUD 0x03U
#define UPDATE_TYPE_NONE      0xFFU

#ifdef SOC_REMAP_ENABLE

#ifdef SOC_IMXRT1170_SERIES
#define REMAPADDRSTART  0x400CC420
#define REMAPADDREND    0x400CC424
#define REMAPADDROFFSET 0x400CC428
#else
#define REMAPADDRSTART  0x400AC078
#define REMAPADDREND    0x400AC07C
#define REMAPADDROFFSET 0x400AC080
#endif

struct remap_trailer {
    uint8_t image_position;
    uint8_t pad1[7];
    uint8_t image_ok;
    uint8_t pad2[7];
    uint8_t magic[16];
};
#define IMAGE_TRAILER_SIZE     sizeof(struct remap_trailer)
#else
struct swap_trailer {
    uint8_t copy_done;
    uint8_t pad1[7];
    uint8_t image_ok;
    uint8_t pad2[7];
    uint8_t magic[16];
};
#define IMAGE_TRAILER_SIZE     sizeof(struct swap_trailer)
#endif

/* write the image trailer at the end of the flash partition */
void enable_image(void);

void write_image_ok(void);

#ifdef MCUBOOT_IMAGE
int8_t compare_image_version(const struct image_version *version1, const struct image_version *version2);
#endif


void write_update_type(uint8_t type);

uint8_t read_ota_status(void);

void print_image_version(void);

#ifdef SOC_REMAP_ENABLE
void SBL_EnableRemap(uint32_t start_addr, uint32_t end_addr, uint32_t off);
void SBL_DisableRemap(void);
#endif


#endif

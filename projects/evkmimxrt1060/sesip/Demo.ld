GROUP (
  "libgcc.a"
  "libc.a"
  "libm.a"
  "libcr_newlib_none.a"
  "libnosys.a"
)

/*
 *   LPC54018 does not execute from Flash but from RAM (SRAM_DTC). As a result, the
 *   MPU needs to be programmed to set the portion of SRAM_DTC containing kernel
 *   code as privileged Read Only and the portion of SRAM_DTC containing remaining
 *   of the code as Read Only. To facilitate this, SRAM_DTC is divided into two
 *   parts:
 *       1. SRAM_DTC_CODE - 128KB. Contains code.
 *       2. SRAM_DTC_DATA - 64 KB. Contains data (only stack and heap as of now).
 *
 *   SRAM_0_1_2_3 is of size 160 KB which is not a power of 2. ARM v7 MPU requires
 *   the size of an MPU region to be a power of two. Since FreeRTOS Cortex M4 MPU
 *   port programs MPU to grant access to all SRAM (for tasks created using
 *   xTaskCreate), we need to ensure that the size of SRAM region is a power of
 *   two. This is why SRAM_0_1_2_3 is divided into two parts:
 *       1. SRAM_0_1_2_3 - 128 KB. Contains data. Since the size is now a power
 *          of two, an MPU region can be used to grant access to it.
 *       2. SRAM_0_1_2_3_UNUSED - 32 KB. Unused.
 */

/* 512KB OCRAM shared between ITCM/DTCM and OCRAM, as well as dedicated 512KB OCRAM */
MEMORY
{
  /* Define each memory region */
  BOARD_FLASH (rx) : ORIGIN = 0x60040400, LENGTH = 0x1ffc00 /* 2047K bytes (alias Flash) == Why not start at 0x60000000 + 0x800000. This seems in between...    */
  SRAM_DTC (rwx) : ORIGIN = 0x20000000, LENGTH = 0x20000 /* 128K bytes (alias RAM) == DTCM */
  SRAM_ITC (rwx) : ORIGIN = 0x0, LENGTH = 0x20000 /* 128K bytes (alias RAM2) == ITCM */
  SRAM_OC (rwx) : ORIGIN = 0x20200000, LENGTH = 0xc0000 /* 768K bytes (alias RAM3) == OCRAM-FleRAM + OCRAM2. Max of 1M. */
  BOARD_SDRAM (rwx) : ORIGIN = 0x80000000, LENGTH = 0x1e00000 /* 30M bytes (alias RAM4) == SDRAM: Can be 32MB at max. */ 
  NCACHE_REGION (rwx) : ORIGIN = 0x81e00000, LENGTH = 0x200000 /* 2M bytes (alias RAM5) == SEMC external memories (SDRAM, NOR, PSRAM, NAND and 8080) shared memory space */
}

  /* Define a symbol for the top of each memory region */
  __base_BOARD_FLASH = 0x60040400  ; /* BOARD_FLASH */  
  __base_Flash = 0x60040400 ; /* Flash */  
  __top_BOARD_FLASH = 0x60040400 + 0x1ffc00 ; /* 2047K bytes */  
  __top_Flash = 0x60040400 + 0x1ffc00 ; /* 2047K bytes */  
  __base_SRAM_DTC = 0x20000000  ; /* SRAM_DTC */  
  __base_RAM = 0x20000000 ; /* RAM */  
  __top_SRAM_DTC = 0x20000000 + 0x20000 ; /* 128K bytes */  
  __top_RAM = 0x20000000 + 0x20000 ; /* 128K bytes */  
  __base_SRAM_ITC = 0x0  ; /* SRAM_ITC */  
  __base_RAM2 = 0x0 ; /* RAM2 */  
  __top_SRAM_ITC = 0x0 + 0x20000 ; /* 128K bytes */  
  __top_RAM2 = 0x0 + 0x20000 ; /* 128K bytes */  
  __base_SRAM_OC = 0x20200000  ; /* SRAM_OC */  
  __base_RAM3 = 0x20200000 ; /* RAM3 */  
  __top_SRAM_OC = 0x20200000 + 0xc0000 ; /* 768K bytes */  
  __top_RAM3 = 0x20200000 + 0xc0000 ; /* 768K bytes */  
  __base_BOARD_SDRAM = 0x80000000  ; /* BOARD_SDRAM */  
  __base_RAM4 = 0x80000000 ; /* RAM4 */  
  __top_BOARD_SDRAM = 0x80000000 + 0x1e00000 ; /* 30M bytes */  
  __top_RAM4 = 0x80000000 + 0x1e00000 ; /* 30M bytes */  
  __base_NCACHE_REGION = 0x81e00000  ; /* NCACHE_REGION */  
  __base_RAM5 = 0x81e00000 ; /* RAM5 */  
  __top_NCACHE_REGION = 0x81e00000 + 0x200000 ; /* 2M bytes */  
  __top_RAM5 = 0x81e00000 + 0x200000 ; /* 2M bytes */


/* Privilegd fuctions are stored are stored in FLash (VMA/LMA) and XIP. */
__privileged_functions_region_size__  = 64K;
__privileged_data_region_size__       = 120K;

/* Symbols needed by the MPU setup code. */
__FLASH_segment_start__ = ORIGIN( BOARD_FLASH );
__FLASH_segment_end__   = __FLASH_segment_start__ + LENGTH( BOARD_FLASH );

__SRAM_segment_start__  = ORIGIN( SRAM_DTC );
__SRAM_segment_end__    = __SRAM_segment_start__ + LENGTH( SRAM_DTC );

ENTRY(ResetISR)

SECTIONS
{
     /* MAIN TEXT SECTION */
    .privileged_functions : ALIGN(4)
    {
        FILL(0xff)
        __vectors_start__ = .;
        __FLASH_segment_start__ = __vectors_start__;
        __privileged_functions_start__ = __vectors_start__;
        
        /* Add in the list of all ISR vectors. */
        KEEP(*(.isr_vector))
        /* Global Section Table */
        . = ALIGN(4) ;
        __section_table_start = .;
        __data_section_table = .;
        
        /* SRAM_DTC */
        LONG(LOADADDR(.data));
        LONG(    ADDR(.data));
        LONG(  SIZEOF(.data));
        
        /* SRAM_ITC */
        LONG(LOADADDR(.data_RAM2));
        LONG(    ADDR(.data_RAM2));
        LONG(  SIZEOF(.data_RAM2));
        
        /* SRAM_OC */
        LONG(LOADADDR(.data_RAM3));
        LONG(    ADDR(.data_RAM3));
        LONG(  SIZEOF(.data_RAM3));
        
        /* BOARD_SDRAM */
        LONG(LOADADDR(.data_RAM4));
        LONG(    ADDR(.data_RAM4));
        LONG(  SIZEOF(.data_RAM4));
        
        /* NCACHE_REGION */
        LONG(LOADADDR(.data_RAM5));
        LONG(    ADDR(.data_RAM5));
        LONG(  SIZEOF(.data_RAM5));
        __data_section_table_end = .;
        __bss_section_table = .;
        LONG(    ADDR(.bss));
        LONG(  SIZEOF(.bss));
        LONG(    ADDR(.bss_RAM2));
        LONG(  SIZEOF(.bss_RAM2));
        LONG(    ADDR(.bss_RAM3));
        LONG(  SIZEOF(.bss_RAM3));
        LONG(    ADDR(.bss_RAM4));
        LONG(  SIZEOF(.bss_RAM4));
        LONG(    ADDR(.bss_RAM5));
        LONG(  SIZEOF(.bss_RAM5));
        __bss_section_table_end = .;
        __section_table_end = . ;
        /* End of Global Section Table */

        /* Reset ISR and data init functions for the board. */
        *(.after_vectors*)
        
        /* Kernel code. */
        *(privileged_functions)
        
        FILL(0xDEAD);
        
        /* Ensure that non-privileged code is placed after the region reserved for
         * privileged kernel code. */
        /* Note that dot (.) actually refers to the byte offset from the start of
         * the current section (.privileged_functions in this case). As a result,
         * setting dot (.) to a value sets the size of the section. */
        . = __privileged_functions_region_size__;
        __privileged_functions_end__ = .;
    } > BOARD_FLASH
    
    /* Text Section. */
    .text : ALIGN(4)
    {        
        /* Place the FreeRTOS System Calls first in the unprivileged region. */
        __syscalls_flash_start__ = .;
        *(freertos_system_calls)
        __syscalls_flash_end__ = .;

        /* For XIP, some objects need to be in .data. Otherwise place all other .text here + RO data */
        *(EXCLUDE_FILE(*mflash_drv.o *fsl_flexspi.o *ota_pal.o *flexspi_nor_flash_ops.o) .text*)       *(.rodata .rodata.* .constdata .constdata.*)
        KEEP(*freertos*/tasks.o(.rodata*)) /* FreeRTOS Debug Config. */
        . = ALIGN(4);
    } > BOARD_FLASH
    
    /*
     * for exception handling/unwind - some Newlib functions (in common
     * with C++ and STDC++) use this.
     */
    .ARM.extab : ALIGN(4)
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > BOARD_FLASH

    .ARM.exidx : ALIGN(4)
    {
        __exidx_start = .;
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        __exidx_end = .;
    } > BOARD_FLASH
 
    /* End of text section. */
    _etext = .;
        
    /* DATA section for SRAM_ITC */

    .data_RAM2 : ALIGN(4)
    {
        FILL(0xff)
        PROVIDE(__start_data_RAM2 = .) ;
        PROVIDE(__start_data_SRAM_ITC = .) ;
        *(.ramfunc.$RAM2)
        *(.ramfunc.$SRAM_ITC)
        
        *mflash_drv.o(.text .text* .rodata .rodata*)
        *fsl_flexspi.o(.text .text* .rodata .rodata*)
        *ota_pal.o(.text .text* .rodata .rodata*)
        *flexspi_nor_flash_ops.o(.text .text* .rodata .rodata*)
        . = ALIGN(4) ;
        PROVIDE(__end_data_RAM2 = .) ;
        PROVIDE(__end_data_SRAM_ITC = .) ;
     } > SRAM_ITC AT>BOARD_FLASH

    /* DATA section for SRAM_OC */

    .data_RAM3 : ALIGN(4)
    {
        FILL(0xff)
        PROVIDE(__start_data_RAM3 = .) ;
        PROVIDE(__start_data_SRAM_OC = .) ;
        *(.ramfunc.$RAM3)
        *(.ramfunc.$SRAM_OC)
                . = ALIGN(4) ;
        PROVIDE(__end_data_RAM3 = .) ;
        PROVIDE(__end_data_SRAM_OC = .) ;
     } > SRAM_OC AT>BOARD_FLASH

    /* DATA section for BOARD_SDRAM */

    .data_RAM4 : ALIGN(4)
    {
        FILL(0xff)
        PROVIDE(__start_data_RAM4 = .) ;
        PROVIDE(__start_data_BOARD_SDRAM = .) ;
        *(.ramfunc.$RAM4)
        *(.ramfunc.$BOARD_SDRAM)
                . = ALIGN(4) ;
        PROVIDE(__end_data_RAM4 = .) ;
        PROVIDE(__end_data_BOARD_SDRAM = .) ;
     } > BOARD_SDRAM AT>BOARD_FLASH

    /* DATA section for NCACHE_REGION */

    .data_RAM5 : ALIGN(4)
    {
        FILL(0xff)
        PROVIDE(__start_data_RAM5 = .) ;
        PROVIDE(__start_data_NCACHE_REGION = .) ;
        *(.ramfunc.$RAM5)
        *(.ramfunc.$NCACHE_REGION)
                . = ALIGN(4) ;
        PROVIDE(__end_data_RAM5 = .) ;
        PROVIDE(__end_data_NCACHE_REGION = .) ;
     } > NCACHE_REGION AT>BOARD_FLASH

    /* MAIN DATA SECTION */
    .uninit_RESERVED (NOLOAD) : ALIGN(4)
    {
        _start_uninit_RESERVED = .;
        __privileged_data_start__ = _start_uninit_RESERVED;
        KEEP(*(.bss.$RESERVED*))
       . = ALIGN(4) ;
        _end_uninit_RESERVED = .;
    } > SRAM_DTC AT> SRAM_DTC

    /* Main DATA section (SRAM_DTC) */
    .data : ALIGN(4)
    {
       FILL(0xff)
       _data = . ;
       PROVIDE(__start_data_RAM = .) ;
       PROVIDE(__start_data_SRAM_DTC = .) ;
       
       /* FreeRTOS kernel data. */
        *(privileged_data)

        FILL(0xDEAD);
        /* Ensure that non-privileged data is placed after the region reserved for
         * privileged kernel data. */
        /* Note that dot (.) actually refers to the byte offset from the start of
         * the current section (.data in this case). As a result, setting
         * dot (.) to a value extends the size of the section. */
        . = __privileged_data_region_size__;
        __privileged_data_end__ = .;
       
       FILL(0xff)
       *(vtable)
       *(.ramfunc*)
       KEEP(*(CodeQuickAccess))
       KEEP(*(DataQuickAccess))
       *(RamFunction)
       *(NonCacheable.init)
       *(.data*)
       . = ALIGN(4) ;
       _edata = . ;
       PROVIDE(__end_data_RAM = .) ;
       PROVIDE(__end_data_SRAM_DTC = .) ;
    } > SRAM_DTC AT>BOARD_FLASH

    /* BSS section for SRAM_ITC */
    .bss_RAM2 : ALIGN(4)
    {
       PROVIDE(__start_bss_RAM2 = .) ;
       PROVIDE(__start_bss_SRAM_ITC = .) ;
               . = ALIGN (. != 0 ? 4 : 1) ; /* avoid empty segment */
       PROVIDE(__end_bss_RAM2 = .) ;
       PROVIDE(__end_bss_SRAM_ITC = .) ;
    } > SRAM_ITC AT> SRAM_ITC

    /* BSS section for SRAM_OC */
    .bss_RAM3 : ALIGN(4)
    {
       PROVIDE(__start_bss_RAM3 = .) ;
       PROVIDE(__start_bss_SRAM_OC = .) ;
        
        *(.bss*)
       . = ALIGN (. != 0 ? 4 : 1) ; /* avoid empty segment */
       PROVIDE(__end_bss_RAM3 = .) ;
       PROVIDE(__end_bss_SRAM_OC = .) ;
    } > SRAM_OC AT> SRAM_OC

    /* BSS section for BOARD_SDRAM */
    .bss_RAM4 : ALIGN(4)
    {
       PROVIDE(__start_bss_RAM4 = .) ;
       PROVIDE(__start_bss_BOARD_SDRAM = .) ;
               . = ALIGN (. != 0 ? 4 : 1) ; /* avoid empty segment */
       PROVIDE(__end_bss_RAM4 = .) ;
       PROVIDE(__end_bss_BOARD_SDRAM = .) ;
    } > BOARD_SDRAM AT> BOARD_SDRAM

    /* BSS section for NCACHE_REGION */
    .bss_RAM5 : ALIGN(4)
    {
       PROVIDE(__start_bss_RAM5 = .) ;
       PROVIDE(__start_bss_NCACHE_REGION = .) ;
               . = ALIGN (. != 0 ? 4 : 1) ; /* avoid empty segment */
       PROVIDE(__end_bss_RAM5 = .) ;
       PROVIDE(__end_bss_NCACHE_REGION = .) ;
    } > NCACHE_REGION AT> NCACHE_REGION

    /* MAIN BSS SECTION */
    .bss : ALIGN(4)
    {
        _bss = .;
        PROVIDE(__start_bss_RAM = .) ;
        PROVIDE(__start_bss_SRAM_DTC = .) ;
       *(NonCacheable)
        *(.bss*)
        *(COMMON)
        . = ALIGN(4) ;
        _ebss = .;
        PROVIDE(__end_bss_RAM = .) ;
        PROVIDE(__end_bss_SRAM_DTC = .) ;
        PROVIDE(end = .);
    } > SRAM_DTC AT> SRAM_DTC

    /* NOINIT section for SRAM_ITC */
    .noinit_RAM2 (NOLOAD) : ALIGN(4)
    {
       PROVIDE(__start_noinit_RAM2 = .) ;
       PROVIDE(__start_noinit_SRAM_ITC = .) ;
       *(.noinit.$RAM2)
       *(.noinit.$SRAM_ITC)
       *(.noinit.$RAM2.*)
       *(.noinit.$SRAM_ITC.*)
       . = ALIGN(4) ;
       PROVIDE(__end_noinit_RAM2 = .) ;
       PROVIDE(__end_noinit_SRAM_ITC = .) ;
    } > SRAM_ITC AT> SRAM_ITC

    /* NOINIT section for SRAM_OC */
    .noinit_RAM3 (NOLOAD) : ALIGN(4)
    {
       PROVIDE(__start_noinit_RAM3 = .) ;
       PROVIDE(__start_noinit_SRAM_OC = .) ;
       *(.noinit.$RAM3)
       *(.noinit.$SRAM_OC)
       *(.noinit.$RAM3.*)
       *(.noinit.$SRAM_OC.*)
       . = ALIGN(4) ;
       PROVIDE(__end_noinit_RAM3 = .) ;
       PROVIDE(__end_noinit_SRAM_OC = .) ;
    } > SRAM_OC AT> SRAM_OC

    /* NOINIT section for BOARD_SDRAM */
    .noinit_RAM4 (NOLOAD) : ALIGN(4)
    {
       PROVIDE(__start_noinit_RAM4 = .) ;
       PROVIDE(__start_noinit_BOARD_SDRAM = .) ;
       *(.noinit.$RAM4)
       *(.noinit.$BOARD_SDRAM)
       *(.noinit.$RAM4.*)
       *(.noinit.$BOARD_SDRAM.*)
       . = ALIGN(4) ;
       PROVIDE(__end_noinit_RAM4 = .) ;
       PROVIDE(__end_noinit_BOARD_SDRAM = .) ;
    } > BOARD_SDRAM AT> BOARD_SDRAM

    /* NOINIT section for NCACHE_REGION */
    .noinit_RAM5 (NOLOAD) : ALIGN(4)
    {
       PROVIDE(__start_noinit_RAM5 = .) ;
       PROVIDE(__start_noinit_NCACHE_REGION = .) ;
       *(.noinit.$RAM5)
       *(.noinit.$NCACHE_REGION)
       *(.noinit.$RAM5.*)
       *(.noinit.$NCACHE_REGION.*)
       . = ALIGN(4) ;
       PROVIDE(__end_noinit_RAM5 = .) ;
       PROVIDE(__end_noinit_NCACHE_REGION = .) ;
    } > NCACHE_REGION AT> NCACHE_REGION

    /* DEFAULT NOINIT SECTION */
    .noinit (NOLOAD): ALIGN(4)
    {
        _noinit = .;
        PROVIDE(__start_noinit_RAM = .) ;
        PROVIDE(__start_noinit_SRAM_DTC = .) ;
        *(.noinit*)
         . = ALIGN(4) ;
        _end_noinit = .;
       PROVIDE(__end_noinit_RAM = .) ;
       PROVIDE(__end_noinit_SRAM_DTC = .) ;        
    } > SRAM_DTC AT> SRAM_DTC

    /* What is this? For now, this doesn't seem to be used anywhere. */
    /* Reserve and place Heap within memory map */
    _HeapSize = 0x1000;
    .heap (NOLOAD) :  ALIGN(4)
    {
        _pvHeapStart = .;
        . += _HeapSize;
        . = ALIGN(4);
        _pvHeapLimit = .;
    } > SRAM_ITC

     
     _StackSize = 0x1000;
     /* Reserve space in memory for Stack */
    .heap2stackfill (NOLOAD) :
    {
        . += _StackSize;
    } > SRAM_ITC

    /* Locate actual Stack in memory map */
    .stack ORIGIN(SRAM_DTC) + LENGTH(SRAM_DTC) - _StackSize - 0 (NOLOAD) :  ALIGN(4)
    {
        _vStackBase = .;
        . = ALIGN(4);
        _vStackTop = . + _StackSize;
    } > SRAM_ITC

    /* Provide basic symbols giving location and size of main text
     * block, including initial values of RW data sections. Note that
     * these will need extending to give a complete picture with
     * complex images (e.g multiple Flash banks).
     */
    _image_start = LOADADDR(.privileged_functions );
    _image_end = LOADADDR(.data) + SIZEOF(.data);
    _image_size = _image_end - _image_start;
}
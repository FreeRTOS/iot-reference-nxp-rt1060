/*****************************************************************************
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef __gnu_linux__
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>      /* For mode constants */
#ifdef __gnu_linux__
#include <sys/ioctl.h>
#endif
#include <fcntl.h>         /* For O_* constants */
#ifdef __gnu_linux__
#include <sys/sem.h>
#include <sys/shm.h>
#endif
#include <time.h>
#include <signal.h>

#include "sm_printf.h"
#include "sm_types.h"
#include "ax_cryptoIpc.h"

/*Local Defines*/

#ifndef TGT_A71CH
/************** Shared Mem for SCI2C Sequence Num *********/
static key_t Shmkey = 56789; /*TODO: Use ftok to get a unique ID, declared in sci2c.c*/
static int CryptoIpc_ShmId;
static char *pShm = NULL;

/************** Semaphore Mutex ************************/
static key_t Semkey = 12345; /*TODO: Use ftok to get a unique ID*/
static int CryptoIpc_SemId;
static U16 CryptoIpc_SemVal;

/* This flag marks if the application is currently holding the Mutex. Used before releasing the IPC resources when
 * CryptoIpc_Close is invoked */
static int CryptoIpc_SemLocked = AX_CI_FALSE;
/* This flag is set when IPC cleanup has to be deferred as the app is holding the mutex. If this flag is set , then
 * upon invocation of CryptoIpc_MutexUnlock(), the IPC resouces are cleaned and application exits*/
static int CryptoIpc_FlagExit = AX_CI_FALSE;

struct sembuf CryptoIpc_SemWait, CryptoIpc_SemSignal;
#endif

/**
 Initialization for Crypto Library Mutex. This should be invoked as part of App initialization.
 Note:- In a system only 1 application (and the first one to be launched)  shall invoke this
 API with parameter AX_CI_TRUE. All other API's invoke with parameter AX_CI_FALSE.

 * @param bool - AX_CI_TRUE - set mutex value to 1, AX_CI_FALSE- Do not set Mutex val
 * @return 0 always
 */
int CryptoIpc_MutexInit(int setval)
{
#ifdef TGT_A71CH
    return 0;
#else
    CryptoIpc_SemWait.sem_num = 0;
    CryptoIpc_SemWait.sem_op = -1;
    CryptoIpc_SemWait.sem_flg = SEM_UNDO; /*In case the application is terminated intentionally or unintentionally*/

    CryptoIpc_SemSignal.sem_num = 0;
    CryptoIpc_SemSignal.sem_op = 1;
    CryptoIpc_SemSignal.sem_flg = SEM_UNDO; /*In case the application is terminated intentionally or unintentionally*/

    // TODO: Investigate why the function argument is overruled
    setval = AX_CI_TRUE;
    CryptoIpc_SemId = semget(Semkey,1,IPC_CREAT|IPC_EXCL|777);
    if (CryptoIpc_SemId == -1)
    {
        if (errno == EEXIST)
        {
            printf("Semaphore already exists\n");
            CryptoIpc_SemId = semget(Semkey, 1, IPC_CREAT|777);
            setval = AX_CI_FALSE;
        }
        else
        {
            printf("Semaphore Creation failed\n");
        }
        return 1;
    }

    printf("Allocating the semaphore: %d %d\n",errno,CryptoIpc_SemId);
    if (setval == AX_CI_TRUE)
    {
        CryptoIpc_SemVal = 1; /*Mutex*/
        semctl(CryptoIpc_SemId, 0, SETVAL, CryptoIpc_SemVal);
        printf("Setting semaphore value to %d: %d\n", CryptoIpc_SemVal, errno);
    }
    else
    {
        //printf("Initialized Semaphore value to %d: %d\n",CryptoIpc_SemVal,errno);
    }

    return 0;
#endif
}

/**
 * Initialization for Crypto Library shared memory.
 * The sequence number used in the PCB byte of SCI2C is placed in this
 * shared memory as the Secure Element just goes by Command Response
 * Sequence and the number of applications on the host is transparent
 * to the Secure Element.
 * This API is invoked as part of SCI2C initialization. Not to be invoked by the app.
 * \note Not used.
 *
 * @return shared memory segment
 */
char *CryptoIpc_ShmInit(void)
{
#ifdef TGT_A71CH
	return NULL;
#else
    /*  create the segment */
    if ((CryptoIpc_ShmId = shmget(Shmkey, 4, 0644 | IPC_CREAT)) == -1)
    {
        printf("CryptoIpc: shmget failed\n");
    }
    else
    {
        //printf("CryptoIpc: SHMID is %d",shmid);
    }
    /* Now we attach the segment to our data space. */
    if ((pShm = (char*)shmat(CryptoIpc_ShmId, NULL, 0)) == (char *) -1)
    {
        printf("CryptoIpc: shmat failed\n");
        return NULL;
    }
    return pShm;
#endif
}

/**
 * Grab mutex before entering Critical Section
 * @return void
 */
void CryptoIpc_MutexLock()
{
#ifdef TGT_A71CH
    return;
#else
    CryptoIpc_SemLocked = AX_CI_TRUE;
    semop(CryptoIpc_SemId, &CryptoIpc_SemWait, 1);
#endif
}

/**
 * Release mutex and after exit from Critical Section
 * @return void
 */
void CryptoIpc_MutexUnlock()
{
#ifdef TGT_A71CH
    return;
#else
    CryptoIpc_SemLocked = AX_CI_FALSE;
    semop(CryptoIpc_SemId, &CryptoIpc_SemSignal, 1);
    if (CryptoIpc_FlagExit == AX_CI_TRUE)
    {
        if (AX_CI_TRUE == CryptoIpc_Close())
        {
            printf("CryptoIpc: Cleaned..Good Bye...\n");
            exit(0);
        }
    }
#endif
}

/**
 * Clean up of IPC resources. API to be invoked at App exit
 * @retval AX_CI_TRUE: OK to exit application
 * @retval AX_CI_FALSE: Application is in Critical section and shall clean up upon out from Critical Section. And then invoke App exit().
 */
int CryptoIpc_Close()
{
#ifdef TGT_A71CH
    return AX_CI_TRUE;
#else
    /*Wait for the mutex to be released*/
    if (CryptoIpc_SemLocked)
    {
        CryptoIpc_FlagExit = AX_CI_TRUE;
        return AX_CI_FALSE;
    }
    shmdt(pShm); /* Detach the shared memory */
    shmctl (CryptoIpc_ShmId, IPC_RMID, 0);

    return AX_CI_TRUE;
#endif
}

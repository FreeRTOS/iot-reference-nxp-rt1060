/**
 * @file accessManager.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Connection Oriented TCP/IP Server implementing JRCP_V1 protocol for
 * incoming connections.
 * Several client processes can connect in parallel to server process.
 * The server can connect to the secure element via the
 * - SCI2C protocol (not tested)
 * - T1oI2C protocol
 * @par History
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>        // memset
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef ENABLE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "sm_apdu.h"
#include "accessManager.h"
#include "accessManager_com.h"

#if defined(SCI2C)
#include "apduComm.h"
#include "sci2c.h"
#endif

#define BACKLOG 10        // how many pending connections queue will hold
#define ACCESS_MGR_VERSION_MAJOR 1
#define ACCESS_MGR_VERSION_MINOR 0

#define ERROR_VERBOSE

#ifndef FLOW_VERBOSE
#define FLOW_VERBOSE
#endif

// #ifndef APDU_VERBOSE
// #define APDU_VERBOSE
// #endif

// #define DBG_VERBOSE

#ifdef ERROR_VERBOSE
#define EPRINTF(...) printf (__VA_ARGS__)
#else
#define EPRINTF(...)
#endif

#ifdef APDU_VERBOSE
#define APRINTF(...) printf (__VA_ARGS__)
#else
#define APRINTF(...)
#endif

#ifdef FLOW_VERBOSE
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

#ifdef DBG_VERBOSE
#define DPRINTF(...) printf (__VA_ARGS__)
#else
#define DPRINTF(...)
#endif


// #include "demoAccessManagerConfig.h"

/* data structures */
typedef struct client_struct {
  int                  sock;
  /* place additional client attributes here */
  int                  nLock;
  struct client_struct *next;
} client_t;

client_t* addClient(client_t *head, int sock);
client_t* removeObsoleteClients(client_t *head, int *fOnHold);

#define WRITECHECK(x)   { if((x) < 0) { \
                          fprintf(stderr, "Connection to client %d unexpectedly closed.\n", cl->sock); \
                          cl->sock = -1; \
                          cl = cl->next; \
                          continue;} \
                        }

#if 0
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
#endif

static void cmdLineArgHelp(char *szProgName);
static int cmdLineParsing(int argc, char **argv, bool *requestPlatformSCP03, bool *requestAnyAddressBinding);

int main(int argc, char ** argv)
{
    int listeningSock;
    struct sockaddr_in server;
    uint16_t serverPort = SERVERPORT;

    // Client data structure
    client_t *clientHead = NULL;
    int fOnHold = 0;

    int fServe = 1;
    int socketType;
    int yes = 1;

    // struct addrinfo hints, *servinfo, *p;
    // struct sockaddr_storage their_addr; // connector's address information
    // socklen_t sin_size;
    struct sigaction sa;
    char s[INET6_ADDRSTRLEN];
    int rv;
    U8 sndBuf[MSG_SIZE];             // Outgoung data sent over socket
    U16 sndBufLen = sizeof(sndBuf);
    uint8_t  rcvBuf[MSG_SIZE];       // Incoming data received over socket
    U16 statusValue = 0;
    U8 respBuf[MSG_SIZE];            // APDU Response buffer
    U16 respBufLen = sizeof(respBuf);
    static bool sessionOpen =  FALSE;
    static bool appletSelected = FALSE;
    static bool requestPlatformSCP03 = TRUE;
    static bool requestAnyAddressBinding = FALSE;
    int nCmdLineParseStatus = 0;
    static U8 platformSCP03_On = 0;

#if SSS_HAVE_A71CH
    U8 cmdAppletSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x05, 0x61, 0x37, 0x31, 0x63, 0x68, 0x00};
#else
    U8 cmdAppletSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x03, 0x96,
                                  0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif
    static U8 rspAppletSelect[128];
    static size_t rspAppletSelectLen = 0;

    U16 connectStatus = 0;
#if defined(SCI2C) || defined(PCSC) || defined(SMCOM_JRCP_V2) || defined(T1oI2C)
    U8 Atr[64];
    U16 AtrLen = sizeof(Atr);
    SmCommStateAm_t commState;
    // Scp03SessionState_t sessionState;
#endif

    // Deal with command line arguments
    nCmdLineParseStatus = cmdLineParsing(argc, argv, &requestPlatformSCP03, &requestAnyAddressBinding);
    if (nCmdLineParseStatus == -1) {
        cmdLineArgHelp(argv[0]);
        return -1;
    }

    printf("Starting accessManager (Rev.%d.%d).\n", ACCESS_MGR_VERSION_MAJOR, ACCESS_MGR_VERSION_MINOR);
    printf("  Protect Link between accessManager and SE: %s.\n", (requestPlatformSCP03 == TRUE) ? "YES" : "NO");

    // int socket(int domain , int type , int protocol );
    //      Returns file descriptor on success, or –1 on error
    // For IPC we can also use domain 'AF_UNIX'

    // Setup socket
    // NOTE: Linux defines two non-standard flags for the type parameter of the socket function
    // The SOCK_NONBLOCK flag (one of them) causes the kernel to set the O_NONBLOCK flag on the
    // underlying open file description, so that future I/O operations on the socket will be nonblocking.
    // This saves additional calls to fcntl() to achieve the same result.
    socketType = SOCK_STREAM;
#ifdef __gnu_linux__
    socketType |= SOCK_NONBLOCK;
#else
    EPRINTF("Check whether listening socket must be non-blocking.\n");
#endif
    listeningSock = socket(AF_INET, socketType, 0);
    if (listeningSock < 0) {
        perror("socket");
        return MCS_SOCKET_FAILURE;
    }
    if (setsockopt(listeningSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)))
    {
        perror("setsockopt");
        return MCS_SOCKET_FAILURE;
    }
    memset(&server, 0x00, sizeof(server));
    server.sin_family = AF_INET;
    if (requestAnyAddressBinding) {
        server.sin_addr.s_addr = INADDR_ANY;
    }
    else {
        server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    server.sin_port = htons(serverPort);
    if (bind(listeningSock, (struct sockaddr*) &server, sizeof(server))) {
        perror("bind");
        return EXIT_FAILURE;
    }
    if (listen(listeningSock, BACKLOG)) {
        perror("listen");
        return EXIT_FAILURE;
    }

#if defined(SCI2C)
    printf("accessManager JRCPv1 (SCI2C SE side)\n");
    #if defined(TGT_A71CH) || defined(TGT_A71CL)
        printf("A71 (I2C_CLK_MAX = 400 kHz) - Effective Master Clock depends on Host Platform.\n");
    #else
        printf("A70 (I2C_CLK_MAX = 100 kHz) - Effective Master Clock depends on Host Platform.\n");
    #endif
#elif defined (PCSC)
    printf("accessManager JRCPv1 (PCSC SE side)\n");
#elif defined(SMCOM_JRCP_V2)
    printf("accessManager JRCPv1 (JRCPv2 SE side)\n");
#elif defined(T1oI2C)
    printf("accessManager JRCPv1 (T1oI2C SE side)\n");
#else
    #error "No SE side interconnect defined: supported are T1oI2C, SCI2C and PCSC"
#endif
    printf("******************************************************************************\n");
    printf("Server: waiting for connections on port %d.\n", serverPort);
    switch (ntohl(server.sin_addr.s_addr)) {
        case INADDR_LOOPBACK:
        printf("Server: only localhost based processes can connect.\n");
        break;

        case INADDR_ANY:
        printf("Server: ** WARNING ** accessManager reacheable over network ** WARNING **\n");
        break;

        default:
        printf("Server: ** WARNING ** accessManager may be reacheable over network ** WARNING **\n");
        break;
    }

#ifdef ENABLE_SD_NOTIFY
    sd_notify(0, "READY=1");
#endif

    while (fServe == 1) {
        fd_set   sockets;
        int      maxfd = listeningSock;
        client_t *cl;
        int nStatus;
        int lockRequested = 0;
        bool sendToApplet = TRUE;

        /* create set of file descriptors (=sockets) */
        FD_ZERO(&sockets);
        FD_SET(listeningSock, &sockets);

        /* clean up list of clients */
        DPRINTF("* clean up list of clients *\n");
        clientHead = removeObsoleteClients(clientHead, &fOnHold);
        cl = clientHead;

        while (cl != NULL) {
            if ( (fOnHold == 1) && (cl->nLock > 0) ) {
                // Only the locking client may listen on socket
                if (cl->sock >= 0) {
                    DPRINTF("Adding socket %d (line=%d)\n", cl->sock, __LINE__);
                    FD_SET(cl->sock, &sockets);
                    maxfd = (maxfd > cl->sock) ? maxfd : cl->sock;
                }
            }
            else if (fOnHold == 0) {
                if (cl->sock >= 0) {
                    DPRINTF("Adding socket %d (line=%d)\n", cl->sock, __LINE__);
                    FD_SET(cl->sock, &sockets);
                    maxfd = (maxfd > cl->sock) ? maxfd : cl->sock;
                }
            }
            cl = cl->next;
        }

        /* wait for new connections or data on existing connections */
        select(maxfd + 1, &sockets, NULL, NULL, NULL);


        U8 emptyDbgInfo[] = {MTY_DEBUG_INFORMATION, 0x00, 0x00, 0x00};
        U8 emptyTerminalInfo[] = {MTY_TERMINAL_INFO, 0x00, 0x00, 0x00};

        /* look for data from clients */
        cl = clientHead;
        while ( (cl != NULL) && (lockRequested != 1) && (fServe == 1)) {
            if (FD_ISSET(cl->sock, &sockets)) {
                char       *pData;
                const char *separator = ":";
                int        nByte;
                int        nPendingData = 0;

                DPRINTF(" Read client message header\n");
                // Read client message header
                nByte = recv(cl->sock, rcvBuf, MSG_HEADER_SIZE, MSG_WAITALL);
                if (nByte == 0) { /* if select marks descriptor as ready, but no data can be read the connection has been closed */
                    printf("Received 0 byte from client %d (Message Header Phase) .\n", cl->sock);
                    close(cl->sock);
                    cl->sock = -1; /* mark client for deletion */
                    cl = cl->next;
                    continue;
                }
                else if (nByte == -1) {
                    EPRINTF("Error on reading: errno: %s.\n", strerror(errno));
                    cl->sock = -1; /* mark client for deletion */
                    cl = cl->next;
                    continue;
                }
                else if (nByte < MSG_HEADER_SIZE) {
                    EPRINTF("Expected to handle a header of size 4. Actual size = %d.", nByte);
                    close(cl->sock);
                    cl->sock = -1; /* mark client for deletion */
                    cl = cl->next;
                    continue;
                }

                // We know we received at least 4 byte
                nPendingData = ((rcvBuf[LNH_IDX] << 8) + rcvBuf[LNL_IDX]) & 0x0FFFF;
                DPRINTF("Command Data Payload = %d\n", nPendingData);

                // Read the remaining data
                if (nPendingData > (MSG_SIZE-MSG_HEADER_SIZE)) {
                    EPRINTF("rcvBuf to small to contain incoming command.\n");
                    close(cl->sock);
                    cl->sock = -1; /* mark client for deletion */
                    cl = cl->next;
                    continue;
                }

                if (nPendingData > 0) {
                    nByte = recv(cl->sock, &rcvBuf[MSG_HEADER_SIZE], nPendingData, 0);
                    if (nByte == 0) { /* if select marks descriptor as ready, but no data can be read the connection has been closed */
                        EPRINTF("Connection to client %d closed (Payload Phase).\n", cl->sock);
                        close(cl->sock);
                        cl->sock = -1; /* mark client for deletion */
                        cl = cl->next;
                        continue;
                    }
                    else if (nByte == -1) {
                        EPRINTF("Error on reading: errno: %s.\n", strerror(errno));
                        cl->sock = -1; /* mark client for deletion */
                        cl = cl->next;
                        continue;
                    }
                    else if (nByte < nPendingData) {
                        EPRINTF("Expected a command payload of %d. Actual size = %d.", nPendingData, nByte);
                        close(cl->sock);
                        cl->sock = -1; /* mark client for deletion */
                        cl = cl->next;
                        continue;
                    }
                }

                FPRINTF("Command 0x%02X from client %d\n", rcvBuf[MTY_IDX], cl->sock);
                {
                    int j;
                    for (j=0; j<4 + nPendingData; j++) {
                        DPRINTF("0x%02X:", rcvBuf[j]);
                    }
                    DPRINTF("\n");
                }

                sndBufLen = sizeof(sndBuf);

                // Interpret the message contained in rcvBuf (rcvBuf)
                switch (rcvBuf[MTY_IDX])
                {
                case MTY_WAIT_FOR_CARD:
                    // Handle reset
                    if (sessionOpen)
                    {
                        // Do not reset card connection again.
                        // Return ATR as received on initial connect
                        int i=0;
                        FPRINTF("ATR=0x");
                        for (i=0; i<AtrLen; i++) printf("%02X.", Atr[i]);
                        FPRINTF("\n");
                        sndBufLen = sizeof(sndBuf);
                        statusValue = amPackageApduResponse(MTY_WAIT_FOR_CARD, 0x00, Atr, AtrLen, sndBuf, &sndBufLen);
                        if (statusValue == AM_OK)
                        {
                            // TODO: On Failure log
                            // EPRINTF("Returning ATR to JCShell client failed\n");
                            WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                            sessionOpen = TRUE;
                        }
                        else
                        {
                            EPRINTF("Could not package APDU response (Line=%d).\n", __LINE__);
                        }
                    }
                    else
                    {
                        DPRINTF("Establish connection and issue an ATR.\n");
                        AtrLen = sizeof(Atr);
                        connectStatus = SM_ConnectAm(&commState, Atr, &AtrLen);
                        if (connectStatus != SW_OK)
                        {
                            U8 errMsg[] = {MTY_WAIT_FOR_CARD, 0x00, 0x00, 0x00};
                            EPRINTF("Failed to establish connection to Secure Module: 0x%04X\n", connectStatus);
                            WRITECHECK(write(cl->sock, errMsg, sizeof(errMsg)));
                        }
                        else
                        {
                            int i=0;
                            FPRINTF("ATR=0x");
                            for (i=0; i<AtrLen; i++) printf("%02X.", Atr[i]);
                            FPRINTF("\n");
                            sndBufLen = sizeof(sndBuf);
                            statusValue = amPackageApduResponse(MTY_WAIT_FOR_CARD, 0x00, Atr, AtrLen, sndBuf, &sndBufLen);
                            if (statusValue == AM_OK)
                            {
                                // TODO: On Failure log
                                // EPRINTF("Returning ATR to JCShell client failed\n");
                                WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                                sessionOpen = TRUE;
                            }
                            else
                            {
                                EPRINTF("Could not package APDU response (Line=%d).\n", __LINE__);
                            }
                        }
                    }
                    break;
                case MTY_APDU_DATA:
                    respBufLen = sizeof(respBuf);
                    sendToApplet = TRUE;

                    // TRACE PRINT BEGIN
                    APRINTF("0x");
                    {
                        int nLoop = 0;
                        for (nLoop = 0; nLoop < nPendingData; nLoop++) {
                            APRINTF("%02X.", rcvBuf[DATA_START_IDX+nLoop]);
                        }
                    }
                    APRINTF("\n");
                    // TRACE PRINT END

                    if (appletSelected)
                    {
#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
                        U8 cmdCardmanagerSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
                        U8 rspCardmanagerSelect[] = { 0x00 };
#else
                        U8 cmdCardmanagerSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
                        U8 rspCardmanagerSelect[] = { 0x6F, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00,
                            0x00, 0x00, 0xA5, 0x04, 0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif
                        statusValue = SW_OK;

                        if ( (sizeof(cmdCardmanagerSelect) == nPendingData) &&
                            (memcmp(cmdCardmanagerSelect, &rcvBuf[DATA_START_IDX], nPendingData)) == 0) {
                            sendToApplet = FALSE;
                            FPRINTF("Pre-cooked response (rspCardmanagerSelect)\n");
                            memcpy(respBuf, rspCardmanagerSelect, sizeof(rspCardmanagerSelect));
                            respBufLen = sizeof(rspCardmanagerSelect);
                        }
                        else if ( (sizeof(cmdAppletSelect) == nPendingData) &&
                            (memcmp(cmdAppletSelect, &rcvBuf[DATA_START_IDX], nPendingData)) == 0) {
                            sendToApplet = FALSE;
                            FPRINTF("Pre-cooked response (rspAppletSelect)\n");
                            memcpy(respBuf, rspAppletSelect, rspAppletSelectLen);
                            respBufLen = rspAppletSelectLen;
                        }
                    }
                    else
                    {
                        if ( (sizeof(cmdAppletSelect) == nPendingData) &&
                            (memcmp(cmdAppletSelect, &rcvBuf[DATA_START_IDX], nPendingData)) == 0) {
                            sendToApplet = FALSE;

                            // Send & Interpret result of applet select
                            statusValue = SM_SendAPDUAm(&rcvBuf[DATA_START_IDX], nPendingData, respBuf, &respBufLen, 0);
                            if ( (statusValue == SW_OK) && (respBufLen >= 2) ) {
                                if ( (respBuf[respBufLen-2] == 0x90) && (respBuf[respBufLen-1] == 0x00) ) {
                                    if (respBufLen <= sizeof(rspAppletSelect)) {
                                        rspAppletSelectLen = respBufLen;
                                        memcpy(rspAppletSelect, respBuf, rspAppletSelectLen);
                                        appletSelected = TRUE;
#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
                                        if (respBufLen >= 4) {
                                            commState.appletVersion = (respBuf[0] << 8) + respBuf[1];
                                            if (respBufLen == 6) {
                                                commState.sbVersion = (respBuf[2] << 8) + respBuf[3];
                                            }
                                            else if (respBufLen == 4) {
                                                commState.sbVersion = 0x0000;
                                            }
                                        }
#endif // SSS_HAVE_A71CH / SSS_HAVE_A71CL
#if SSS_HAVE_SE05X
                                        if (respBufLen >= 6) {
                                            // 2.2.4 returns 4 bytes, 2.2.4.[A,B,C]
                                            // 2.3.0 returns 5 bytes, 2.3.0.[v1].[v2]
                                            // 2.5.3 returns 7 bytes,
                                            commState.appletVersion = 0;
                                            commState.appletVersion |= respBuf[0];
                                            commState.appletVersion <<= 8;
                                            commState.appletVersion |= respBuf[1];
                                            commState.appletVersion <<= 8;
                                            commState.appletVersion |= respBuf[2];
                                            commState.appletVersion <<= 8;
                                            // commState.appletVersion |= selectResponseData[3];
                                            commState.sbVersion = 0x0000;
                                        }
                                        else {
                                            EPRINTF("Cannot determine applet version.\n");
                                        }
#endif // SSS_HAVE_SE05X
                                        // Conditionally establish Platform SCP03 session
                                        if (requestPlatformSCP03 == TRUE) {
                                            #if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)
                                                statusValue = SM_EstablishA71CHPlatformSCP03Am();
                                            #else
                                                statusValue = SM_EstablishPlatformSCP03Am(&commState);
                                            #endif
                                            if (statusValue == SW_OK) {
                                                platformSCP03_On = 1;
                                            }
                                            else {
                                                EPRINTF("Cannot establish Platform SCP03.\n");
                                                EPRINTF("Are the correct platform SCP03 keys used?.\n");
                                                EPRINTF("... Requesting server to halt.\n");
                                                cmdLineArgHelp("accessManager");
                                                fServe = 0;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (sendToApplet == TRUE) {
                        statusValue = SM_SendAPDUAm(&rcvBuf[DATA_START_IDX], nPendingData, respBuf, &respBufLen, platformSCP03_On);
                    }
                    if (   (statusValue == SW_OK) ||
                           ( (platformSCP03_On == 1) &&
                                (
                                   (statusValue == SW_CONDITIONS_NOT_SATISFIED) ||
                                   (statusValue == SW_COMMAND_NOT_ALLOWED) ||
                                   (statusValue == SW_WRONG_DATA)
                                )
                           )
                       )
                    {
                        sndBufLen = sizeof(sndBuf);
                        statusValue = amPackageApduResponse(MTY_APDU_DATA, 0x00, respBuf, respBufLen, sndBuf, &sndBufLen);

                        APRINTF("ApduRsp: 0x");
                        {
                            int nLoop = 0;
                            for (nLoop = 0; nLoop < respBufLen; nLoop++) {
                                APRINTF("%02X.", respBuf[nLoop]);
                            }
                        }
                        APRINTF("\n");

                        if (statusValue == AM_OK)
                        {
                            WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                        }
                        else
                        {
                            EPRINTF("Could not package APDU response (Line=%d).\n", __LINE__);
                        }
                    }
                    else
                    {
                        U8 statusArray[2];

                        EPRINTF("SM_SendAPDU failed with statusValue: 0x%04X.\n", statusValue);
                        EPRINTF("********************************************\n");
                        statusArray[0] = (U8)(statusValue << 8);
                        statusArray[1] = (U8)(statusValue);
                        sndBufLen = sizeof(sndBuf);
                        amPackageApduResponse(MTY_APDU_DATA, 0x00, statusArray, 2, sndBuf, &sndBufLen);
                        write(cl->sock, sndBuf, sndBufLen);
                        close(cl->sock);
                        cl->sock = -1;
                        cl = cl->next;
                        continue;
                    }
                    break;
                case MTY_DEBUG_INFORMATION:
                    EPRINTF("Received a debug info message. Return DEBUG_INFO without data payload.\n");
                    WRITECHECK(write(cl->sock, emptyDbgInfo, sizeof(emptyDbgInfo)));
                    break;
                case MTY_TERMINAL_INFO:
                    EPRINTF("Received a terminal info message. Return TERMINAL_INFO without data payload.\n");
                    WRITECHECK(write(cl->sock, emptyTerminalInfo, sizeof(emptyTerminalInfo)));
                    break;
                case MTY_STATUS:
                case MTY_ERROR_MSG:
                case MTY_INITIALIZATION_DATA:
                case MTY_INFORMATION_TEXT:
                    EPRINTF("Don't know how to deal with Message Type 0x%02X.\n", rcvBuf[MTY_IDX]);
                    close(cl->sock);
                    cl->sock = -1;
                    cl = cl->next;
                    continue;
                    break;
#ifdef AM_LOCK_UNLOCK_SUPPORT
                case MTY_LOCK:
                    // Simplistic command validation
                    if (nPendingData != 0) {
                        EPRINTF("No command payload supported: closing connection wuth client.\n");
                        // Mark client for deletion
                        close(cl->sock);
                        cl->sock = -1;
                        cl = cl->next;
                        continue;
                    }
                    cl->nLock += 1;
                    fOnHold = 1;
                    lockRequested = 1;
                    sndBuf[MTY_IDX] = MTY_LOCK;
                    sndBuf[NAD_IDX] = rcvBuf[NAD_IDX];
                    sndBuf[LNH_IDX] = 0x00;
                    sndBuf[LNL_IDX] = 0x00;
                    sndBufLen = 4;
                    WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                    break;

                case MTY_UNLOCK:
                    // Simplistic command validation
                    if (nPendingData != 0) {
                        EPRINTF("No command payload supported: closing connection wuth client.\n");
                        // Mark client for deletion
                        close(cl->sock);
                        cl->sock = -1;
                        cl = cl->next;
                        continue;
                    }
                    cl->nLock -= 1;
                    if (cl->nLock <= 0) {
                        fOnHold = 0;
                    }
                    sndBuf[MTY_IDX] = MTY_UNLOCK;
                    sndBuf[NAD_IDX] = rcvBuf[NAD_IDX];
                    sndBuf[LNH_IDX] = 0x00;
                    sndBuf[LNL_IDX] = 0x00;
                    sndBufLen = 4;
                    WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                    break;
#endif // AM_LOCK_UNLOCK_SUPPORT

#ifndef NDEBUG
                case MTY_QUIT:
                    // Simplistic command validation
                    EPRINTF("GOT QUIT REQ FROM CLIENT\n");
                    fServe = 0;
                    sndBuf[MTY_IDX] = MTY_QUIT;
                    sndBuf[NAD_IDX] = rcvBuf[NAD_IDX];
                    sndBuf[LNH_IDX] = 0x00;
                    sndBuf[LNL_IDX] = 0x00;
                    sndBufLen = 4;
                    WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                    SM_CloseAm(0);
                    break;
#endif
#if 0
                case MTY_SET_UINT32:
                    nStatus = handleSetUint32(rcvBuf, 4 + nPendingData, sndBuf, &sndBufLen);
                    if (nStatus != MCS_OK) {
                        // Mark client for deletion
                        cl->sock = -1;
                        cl = cl->next;
                        continue;
                    }
                    WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                    break;

                case MTY_GET_UINT32:
                    nStatus = handleGetUint32(rcvBuf, 4 + nPendingData, sndBuf, &sndBufLen);
                    if (nStatus != MCS_OK) {
                        // Mark client for deletion
                        cl->sock = -1;
                        cl = cl->next;
                        continue;
                    }
                    WRITECHECK(write(cl->sock, sndBuf, sndBufLen));
                    break;
#endif

                case RESERVED_ID1:
                case RESERVED_ID2:
                case RESERVED_ID3:
                case RESERVED_ID4:
                case RESERVED_ID5:
                case RESERVED_ID6:
                case RESERVED_ID7:
                case RESERVED_ID8:
                {
                    EPRINTF("Message Type not implemented - 0x%02X.\n", rcvBuf[0]);
                }
                break;

                default:
                    EPRINTF("Don't know how to deal with Message Type 0x%02X.\n", rcvBuf[0]);
                    close(cl->sock);
                    cl->sock = -1;
                    cl = cl->next;
                    continue;
                    break;
                }
            }
            cl = cl->next;
        }

        /* handle new client connections, if available */
        if (FD_ISSET(listeningSock, &sockets)) {
            struct sockaddr_in newClient;
            int                newClientFd;
            socklen_t          newClientLen = sizeof(struct sockaddr_in);

            newClientFd = accept(listeningSock, (struct sockaddr *) &newClient, &newClientLen);
            if (newClientFd < 0) {
                fprintf(stderr, "accept() failed.\n");
                return EXIT_FAILURE;
            }
            clientHead = addClient(clientHead, newClientFd);  /* add client to list */
            FPRINTF("New client connection from %d.%d.%d.%d. Client ID: %d\n",
                (newClient.sin_addr.s_addr >> 0) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 8) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 16) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 24) & 0x000000ff,
                newClientFd);

        }
    }
    FPRINTF("Stopping server main program (Rev.%d.%d).\n", ACCESS_MGR_VERSION_MAJOR, ACCESS_MGR_VERSION_MINOR);
    return 0;
}


client_t* addClient(client_t *head, int sock)
{
    client_t *client = head;
    client_t *newClient;

    /* allocate memory for new client */
    newClient = (client_t*)malloc(sizeof(client_t));
    if (newClient == NULL) {
        fprintf(stderr, "Failed to add client; not enough memory!\n");
        exit(EXIT_FAILURE);
    }

    /* initialize client structure */
    memset(newClient, 0x00, sizeof(client_t));
    newClient->sock = sock;
    newClient->nLock = 0;
    newClient->next = NULL;

    /* if list is empty */
    if (head == NULL)
        return newClient;

    /* run to end of list */
    while (client->next != NULL)
        client = client->next;

    /* put client at the end of the list */
    client->next = newClient;

    return head;
}

client_t* removeObsoleteClients(client_t *head, int *fOnHold)
{
    client_t *prevClient, *client;

    while (head != NULL && head->sock < 0) {
        client_t *cl = head;

        head = head->next;
        if (cl->nLock > 0) {
            *fOnHold = 0;
        }
        free(cl);
    }

    if (head == NULL) { // if list is empty, return
        return head;
    }

    client = head->next;
    prevClient = head;
    while (client != NULL) {
        if (client->sock < 0) {
            prevClient->next = client->next;
            if (client->nLock > 0) {
                *fOnHold = 0;
            }
            free(client);
            client = prevClient;
        }
        prevClient = client;
        client = client->next;
    }

    return head;
}


static int cmdLineParsing(int argc, char **argv, bool *requestPlatformSCP03, bool *requestAnyAddressBinding) {
    int nStatus = -1;

    if (argc == 1) {
        // Keep default values
        nStatus = 0;
    }
    else if (argc >= 2) {
        if (argc == 2) {
            if ( strncmp(argv[1], "plain", strlen("plain")) == 0 ) {
                *requestPlatformSCP03 = FALSE;
                nStatus = 0;
            }
            else if ( strncmp(argv[1], "any", strlen("any")) == 0 ) {
                *requestAnyAddressBinding = TRUE;
                nStatus = 0;
            }
        }
        if (argc == 3) {
            if ((strncmp(argv[1], "plain", strlen("plain")) == 0) && (strncmp(argv[2], "any", strlen("any")) == 0)) {
                *requestPlatformSCP03 = FALSE;
                *requestAnyAddressBinding = TRUE;
                nStatus = 0;
            }
            else if ((strncmp(argv[1], "any", strlen("any")) == 0) && (strncmp(argv[2], "plain", strlen("plain")) == 0)) {
                *requestPlatformSCP03 = FALSE;
                *requestAnyAddressBinding = TRUE;
                nStatus = 0;
            }
        }
    }
    return nStatus;
}

static void cmdLineArgHelp(char *szProgName) {
    EPRINTF("%s takes two optional arguments 'plain' & 'any'\n", szProgName);
    EPRINTF("\t'%s':\n", szProgName);
    EPRINTF("\t\tPlatform SCP03: ON.\n");
    EPRINTF("\t\tIncoming connection: localhost.\n");
    EPRINTF("\t'%s plain':\n", szProgName);
    EPRINTF("\t\tPlatform SCP03: OFF.\n");
    EPRINTF("\t\tIncoming connection: localhost.\n");
    EPRINTF("\t'%s any':\n", szProgName);
    EPRINTF("\t\tPlatform SCP03: ON.\n");
    EPRINTF("\t\tIncoming connection: any supported address.\n");
    EPRINTF("\t'%s plain any':\n", szProgName);
    EPRINTF("\t\tPlatform SCP03: OFF.\n");
    EPRINTF("\t\tIncoming connection: any supported address.\n");
    EPRINTF("\n");
    EPRINTF("Note:\n");
    EPRINTF("\tProduct Deployment => Enable Platform SCP03 & restrict incoming connection to localhost\n");
}
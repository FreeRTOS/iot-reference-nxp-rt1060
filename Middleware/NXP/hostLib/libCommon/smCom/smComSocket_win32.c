/**
 * @file smComSocket_win32.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "sm_printf.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "nxLog_smCom.h"
#include "nxEnsure.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#define DEFAULT_PROTO SOCK_STREAM

#define DBG_OUT CONSOLE

#include "smCom.h"
#include "smComSocket.h"

// Enable define of LOG_SOCK to echo APDU cmd/rsp
// #define LOG_SOCK

// Enable define of CHECK_ON_ATR to enable check on returned ATR (don't enable this when using the Smart Card Server ...)
// #define CHECK_ON_ATR

#define REMOTE_JC_SHELL_HEADER_LEN          (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA  (0x01)

#include "sm_apdu.h"
#include "accessManager.h"

#define MAX_BUF_SIZE                (MAX_APDU_BUF_LENGTH)

typedef struct
{
    int sockfd;
    char * ipString;
} socket_Context_t;

static U8 Header[2] = {0x01,0x00};
static U8 sockapdu[MAX_BUF_SIZE];
static U8 response[MAX_BUF_SIZE];
static U8 * pCmd = (U8*) &sockapdu;
static U8 * pRsp = (U8*) &response;

static socket_Context_t sockCtx;
static socket_Context_t* pSockCtx = (socket_Context_t *)&sockCtx;

static U32 smComSocket_GetATR(U8 *pAtr, U16 *atrLen);

U16 smComSocket_Close()
{
    closesocket(pSockCtx->sockfd);
    return SW_OK;
}

U16 smComSocket_Open(void** conn_ctx, U8 *pIpAddrString, U16 portNo, U8 *pAtr, U16 *atrLen)
{
    int retval;
    int nAtr = 0;
    char *server_name= (char*) pIpAddrString;
    int iResult;
    struct addrinfo *result = NULL,
        *ptr = NULL,
        hints;
    char service[128];
    WSADATA wsaData;
    U16 sw = SMCOM_OK;

    if ((retval = WSAStartup(0x202, &wsaData)) != 0)
    {
        sm_printf(DBG_OUT,"WSAStartup failed; error %d\n", retval);
        WSACleanup();
        return SMCOM_COM_FAILED;
    }
    else
    {
#ifdef LOG_SOCK
        sm_printf(DBG_OUT, "WSAStartup: OK\n");
#endif
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    sprintf(service, "%d", portNo);
    iResult = getaddrinfo(server_name, service, &hints, &result);
    if (iResult != 0) {
        sm_printf(DBG_OUT, "getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return SMCOM_COM_FAILED;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        pSockCtx->sockfd = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (pSockCtx->sockfd == INVALID_SOCKET) {
            sm_printf(DBG_OUT, "socket failed with error: %ld\n", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();
            return SMCOM_COM_FAILED;
        }

        // Connect to server.
        iResult = connect(pSockCtx->sockfd, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(pSockCtx->sockfd);
            pSockCtx->sockfd = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (pSockCtx->sockfd == INVALID_SOCKET) {
        sm_printf(DBG_OUT, "Unable to connect to server!\n");
        WSACleanup();
        return SMCOM_COM_FAILED;
    }

    smCom_Init(smComSocket_Transceive, smComSocket_TransceiveRaw);

    nAtr = smComSocket_GetATR(pAtr, atrLen);
#ifdef CHECK_ON_ATR
    // Be aware that the smart card server (java app on PC) does not return the ATR value
    // Do not enable this code when using the smart card server
    if (nAtr == 0)
    {
        sw = SMCOM_NO_ATR;
    }
#endif

    return sw;
}

#if defined(TGT_A70CU)
U16 smComSocket_Init(U8 *pIpAddrString, U16 portNo, U8 *pAtr, U16 *pAtrLength, U16 maxAtrLength)
{
   int retval;
   char *server_name= (char*) pIpAddrString;
   unsigned int addr;
   int socket_type = DEFAULT_PROTO;
   struct sockaddr_in server;
   struct hostent *hp;
   WSADATA wsaData;
   U16 rv = 1;

   ENSURE_OR_GO_EXIT(pIpAddrString != NULL);
   if ((retval = WSAStartup(0x202, &wsaData)) != 0)
   {
      sm_printf(DBG_OUT,"WSAStartup failed; error %d\n", retval);
      WSACleanup();
      return 1;
   }
   else
   {
#ifdef LOG_SOCK
      sm_printf(DBG_OUT, "WSAStartup: OK\n");
#endif
   }

   if (isalpha(server_name[0])) // server address is a name
   {
      hp = gethostbyname(server_name);
   }
   else
   {
      addr = inet_addr(server_name);
      hp = gethostbyaddr((char *)&addr, 4, AF_INET);
   }

   if (hp == NULL )
   {
      sm_printf(DBG_OUT, "Client: Cannot resolve address \"%s\": Error %d\n", server_name, WSAGetLastError());
      WSACleanup();
      return 1;
   }
   else
   {
#ifdef LOG_SOCK
      printf("Client: gethostbyaddr() is OK.\n");
#endif
   }

   memset(&server, 0, sizeof(server));
   memcpy(&(server.sin_addr), hp->h_addr, hp->h_length);

   server.sin_family = hp->h_addrtype;
   server.sin_port = htons(portNo);

   pSockCtx->sockfd = socket(AF_INET, socket_type, 0); /* Open a socket */
   if (pSockCtx->sockfd < 0)
   {
      sm_printf(DBG_OUT, "Client: Error Opening socket: Error %d\n", WSAGetLastError());
      WSACleanup();
      return 1;
   }
   else
   {
#ifdef LOG_SOCK
      sm_printf(DBG_OUT, "Client: socket() is OK.\n");
#endif
   }

   // Notice that nothing in this code is specific to whether we
   // are using UDP or TCP.
   // We achieve this by using a simple trick.
   //    When connect() is called on a datagram socket, it does not
   //    actually establish the connection as a stream (TCP) socket
   //    would. Instead, TCP/IP establishes the remote half of the
   //    (LocalIPAddress, LocalPort, RemoteIP, RemotePort) mapping.
   //    This enables us to use send() and recv() on datagram sockets,
   //    instead of recvfrom() and sendto()
   sm_printf(DBG_OUT, "Client: Client connecting to: %s.\n", hp->h_name);
   if (connect(pSockCtx->sockfd, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
   {
      sm_printf(DBG_OUT, "Client: connect() failed: %d\n", WSAGetLastError());
      WSACleanup();
      return 1;
   }

    smCom_Init(smComSocket_Transceive, smComSocket_TransceiveRaw);

    smComSocket_GetATR(pAtr, pAtrLength);

    rv = 0;
exit:
    return rv;
}
#endif // TGT_A70CU

/**
    Remote JC Terminal spec:
    Wait for card (MTY=0x00)
    The payload contains four bytes denoting the time in milliseconds the remote part will wait for card insertion.
    The bytes are sent in big endian format.

    The reply message contains the full ATR as payload.
    A reply message with 0 bytes length means that the terminal could not trigger an ATR (reason might be retrieved using MTY=3 or MTY=2.
*/
static U32 smComSocket_GetATR(U8* pAtr, U16* atrLen)
{
    int retval = 0;
#if defined(LOG_SOCK) || defined(DBG_LOG_SOCK)
    int i;
#endif
    U32 expectedLength = 0;
    U32 totalReceived = 0;
    U8 lengthReceived = 0;

    // wait 256 ms
    U8 ATRCmd[8] = { MTY_WAIT_FOR_CARD, MYT_DEFAULT_NAD, 0, 4, 0, 0, 1, 0};

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   send: ATR\n");
    for (i=0; i < sizeof(ATRCmd); i++)
    {
       sm_printf(CONSOLE, "%02X", ATRCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    ENSURE_OR_GO_EXIT(pAtr != NULL);
    ENSURE_OR_GO_EXIT(atrLen != NULL);

    retval = send(pSockCtx->sockfd, (const char*) ATRCmd, sizeof(ATRCmd), 0);
    if (retval < 0)
    {
       fprintf(stderr,"Client: send() failed: error %i.\n", retval);
       return 0;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength)
    {
        U32 maxCommLength;
        if (lengthReceived == 0)
        {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else
        {
            maxCommLength = expectedLength - totalReceived;
        }

        retval = recv(pSockCtx->sockfd, (char*) &pAtr[totalReceived], maxCommLength, 0);
        if (retval < 0)
        {
           fprintf(stderr,"Client: recv() failed: error %i.\n", retval);
           closesocket(pSockCtx->sockfd);
           retval = 0;
           goto exit;
        }
        else
        {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0))
        {
            expectedLength += ((pAtr[2]<<8) | (pAtr[3]));
            lengthReceived = 1;
        }
    }
    retval = totalReceived;

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   full recv: ");
    for (i=0; i < retval; i++)
    {
       sm_printf(CONSOLE, "%02X", pAtr[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    memmove(pAtr, pAtr + 4, retval);

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   recv: ");
    for (i=0; i < retval; i++)
    {
       sm_printf(CONSOLE, "%02X", pAtr[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    *atrLen = (U16) retval;
exit:
    return retval;
}

U32 smComSocket_Transceive(void* conn_ctx, apdu_t * pApdu)
{
    int retval;
#if defined(LOG_SOCK)
    int i;
#endif
    U32 txLen = 0;
    U32 expectedLength = 0;
    U32 totalReceived = 0;
    U8 lengthReceived = 0;
    U32 rv = SMCOM_SND_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->rxlen = 0;

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    // remote JC Terminal header construction
    txLen = pApdu->buflen;
    memcpy(pCmd, Header, sizeof(Header));
    pCmd[2] = (txLen& 0xFF00)>>8;
    pCmd[3] = txLen & 0xFF;
    memcpy(&pCmd[4], pApdu->pBuf, pApdu->buflen);
    pApdu->buflen += 4; /* header & length */

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   send: ");
    for (i=4; i < (int)(txLen+4); i++)
    {
       sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    retval = send(pSockCtx->sockfd, (const char*) pCmd, pApdu->buflen, 0);
    if (retval < 0)
    {
       fprintf(stderr,"Client: send() failed: error %i.\n", retval);
       return SMCOM_SND_FAILED;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength)
    {
        retval = recv(pSockCtx->sockfd, (char*) &pRsp[totalReceived], MAX_BUF_SIZE, 0);
        if (retval < 0)
        {
           fprintf(stderr,"Client: recv() failed: error %i.\n", retval);
           closesocket(pSockCtx->sockfd);
           rv = SMCOM_RCV_FAILED;
           goto exit;
        }
        else
        {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0))
        {
            expectedLength += ((pRsp[2]<<8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }
    retval = totalReceived;

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    memcpy(pApdu->pBuf, &pRsp[4], retval);

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   recv: ");
    for (i=0; i < retval; i++)
    {
       sm_printf(CONSOLE, "%02X", pApdu->pBuf[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    pApdu->rxlen = (U16) retval;
    // reset offset for subsequent response parsing
    pApdu->offset = 0;
    rv = SMCOM_OK;
exit:
    return rv;
}

U32 smComSocket_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen)
{
    S32 retval;
    U32 answerReceived = 0;
    U32 len = 0;
#if defined(LOG_SOCK) || defined(DBG_LOG_SOCK)
    int i;
#endif
    U32 readOffset = 0;
    U8 headerParsed = 0;
    U8 correctHeader = 0;
    U32 rv = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pTx != NULL);
    ENSURE_OR_GO_EXIT(pRx != NULL);
    ENSURE_OR_GO_EXIT(pRxLen != NULL);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[2] = (txLen & 0xFF00)>>8;
    pCmd[3] = (txLen & 0x00FF);
    memcpy(&pCmd[4], pTx, txLen);
    txLen += 4; /* header + len */

#ifdef DBG_LOG_SOCK
    sm_printf(CONSOLE, "   full send: ");
    for (i=0; i < txLen; i++)
    {
        sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    retval = send(pSockCtx->sockfd, (const char*) pCmd, txLen, 0);
    if (retval < 0)
    {
        sm_printf(CONSOLE, "Client: send() failed: error %i.\n", retval);
        return SMCOM_SND_FAILED;
    }
    else
    {
#ifdef DBG_LOG_SOCK
        sm_printf(CONSOLE, "Client: send() is OK.\n");
#endif
    }

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   send: ");
    for (i=4; i < txLen; i++)
    {
        sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    retval = REMOTE_JC_SHELL_HEADER_LEN; // receive at least the JCTerminal header

    while ((retval > 0) || (answerReceived == 0))
    {
        retval = recv(pSockCtx->sockfd, (char*) pRsp, MAX_BUF_SIZE, 0);

        if (retval < 0)
        {
           fprintf(stderr,"Client: recv() failed: error %i %x\n", retval, WSAGetLastError());

           closesocket(pSockCtx->sockfd);
           return SMCOM_RCV_FAILED;
        }
        else // data received
        {
            while (retval > 0) // parse all bytes
            {
                if (headerParsed == 1) // header already parsed; get data
                {
                    if (retval >= (S32) len)
                    {
                        if (correctHeader == 1)
                        {
                            memcpy(&pRx[0], &pRsp[readOffset], len);
                            answerReceived = 1;
                        }
                        else
                        {
                            // reset header parsed
                            readOffset += len;
                            headerParsed = 0;
                        }
                        retval -= len;

                        if (retval == 0) // no data left, reset readOffset
                        {
                            readOffset = 0;
                        }
                    }
                    else
                    {
                        // data too small according header => Error
                        fprintf(stderr,"Failed reading data %x %x\n", retval, len);
                        return SMCOM_RCV_FAILED;
                    }
                }
                else // parse header
                {
                    len = ((pRsp[readOffset + 2]<<8) | (pRsp[readOffset + 3]));

                    if (pRsp[readOffset] == REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA)
                    {
                        // type correct => copy the data
                        retval -= REMOTE_JC_SHELL_HEADER_LEN;
                        if (retval > 0) // data left to read
                        {
                            readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        }
                        correctHeader = 1;
                    }
                    else
                    {
                        // type incorrect => skip the data as well and try again if data are left
                        readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        retval -= REMOTE_JC_SHELL_HEADER_LEN;
                        correctHeader = 0;
                    }
                    headerParsed = 1;
                }
            }
        }
    }

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   recv: ");
    for (i=0; i < (int)len; i++)
    {
       sm_printf(CONSOLE, "%02X", pRx[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    *pRxLen = len;

    rv = SMCOM_OK;
exit:
    return rv;
}

U32 smComSocket_LockChannel()
{
    int retval = 0;
    U32 expectedLength = 0;
    U32 totalReceived = 0;

    // wait 256 ms
    U8 LockCmd[4] = { MTY_LOCK, 0, 0, 0};
    U8 LockRsp[4] = { 0,};

    retval = send(pSockCtx->sockfd, (const char*)LockCmd, sizeof(LockCmd), 0);
    if (retval < 0)
    {
        fprintf(stderr, "Client: send() failed: error %i.\n", retval);
        return 0;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength)
    {
        U32 maxCommLength;
        maxCommLength = expectedLength - totalReceived;

        retval = recv(pSockCtx->sockfd, (char*)&LockRsp[totalReceived], maxCommLength, 0);
        if (retval < 0)
        {
            fprintf(stderr, "Client: recv() failed: error %i.\n", retval);
            closesocket(pSockCtx->sockfd);
            retval = 0;
            goto exit;
        }
        else
        {
            totalReceived += retval;
        }
    }
    retval = LockRsp[3];

exit:
    return retval;
}

U32 smComSocket_UnlockChannel()
{
    int retval = 0;
    U32 expectedLength = 0;
    U32 totalReceived = 0;

    // wait 256 ms
    U8 UnLockCmd[4] = { MTY_UNLOCK, 0, 0, 0};
    U8 LockRsp[4] = { 0, };

    retval = send(pSockCtx->sockfd, (const char*)UnLockCmd, sizeof(UnLockCmd), 0);
    if (retval < 0)
    {
        fprintf(stderr, "Client: send() failed: error %i.\n", retval);
        return 0;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength)
    {
        U32 maxCommLength;
        maxCommLength = expectedLength - totalReceived;

        retval = recv(pSockCtx->sockfd, (char*)&LockRsp[totalReceived], maxCommLength, 0);
        if (retval < 0)
        {
            fprintf(stderr, "Client: recv() failed: error %i.\n", retval);
            closesocket(pSockCtx->sockfd);
            retval = 0;
            goto exit;
        }
        else
        {
            totalReceived += retval;
        }
    }
    retval = LockRsp[3];

exit:
    return retval;
}

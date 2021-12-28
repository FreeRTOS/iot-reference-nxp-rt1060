/**
 * @file ID2HLSEWrapper.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Host Lib wrapper API implementation over the A71CL host library
 *
 * @par HISTORY
 *
 */

#include <stdlib.h>
#include "HLSEAPI.h"
#include "a71cl_api.h"
#include "ax_api.h"
#include "nxLog_hostLib.h"

// Storgae size of 5K
#define HLSE_MAX_STORAGE_SIZE   5000

/// Create handle
#define     HLSE_CREATE_HANDLE(HLSE_READ_ONLY, HLSE_OBJECT_TYPE, HLSE_OBJECT_INDEX)   ((HLSE_READ_ONLY ? 0x80000000 : 0x00000000) | HLSE_OBJECT_TYPE | HLSE_OBJECT_INDEX)

/// Get Object Type
#define     HLSE_GET_OBJECT_TYPE(HLSE_OBJECT_HANDLE)                  (HLSE_OBJECT_HANDLE & 0x7FFF0000)
/// Get Object Index
#define     HLSE_GET_OBJECT_INDEX(HLSE_OBJECT_HANDLE)                 (U8)((HLSE_OBJECT_HANDLE & 0x000000FF))
/// Get Object Full Index
#define     HLSE_GET_OBJECT_FULL_INDEX(HLSE_OBJECT_HANDLE)            ((HLSE_OBJECT_HANDLE & 0x0000FFFF))

/// Get Logical object class
#define     HLSE_GET_LOGICAL_OBJECT_CLASS(HLSE_OBJECT_TYPE)           (U8)((HLSE_OBJECT_TYPE & 0x00FF0000) >> 16)
/// Get logical object type
#define     HLSE_GET_LOGICAL_OBJECT_TYPE(objClass)                    ((objClass << 16u) & 0x00FF0000u)


/// Max num of Asymmetric keys supported
#define     HLSE_MAX_ASYMMETRIC_KEYS    1
/// RSA Public key size
#define     HLSE_RSA_PUBLIC_KEY_SIZE    256
/// RSA Public exponent size
#define     HLSE_RSA_PUBLIC_EXPONENT_SIZE    4
/// Maintains the Public key returned by the Secure Element when Key Generation is used
static U8   sPublicKeys[HLSE_MAX_ASYMMETRIC_KEYS][HLSE_RSA_PUBLIC_KEY_SIZE + HLSE_RSA_PUBLIC_EXPONENT_SIZE + 2 + 2];
static U16  sPublicKeysLen[HLSE_MAX_ASYMMETRIC_KEYS];

//*******************************************************************
// Object Operations - defined in HLSEObjects.h
//*******************************************************************

static U8 IsDataValidCertificate(U8* storageData, U16 storageDataLen, U16* certificateSize)
{
    U8 TagLen = 1;
    U16 dataLen = 0;

    if (storageDataLen > 6) {
        // Tag should be 0x30
        if (storageData[0] == 0x30) {
            if ((storageData[1] & 0x1F) == 0x1F) {
                TagLen = 2;
                if (storageData[2] & 0x80) {
                    TagLen = 3;
                }
            }

            if (storageData[TagLen] & 0x80) {
                if (storageData[TagLen] == 0x81)
                    dataLen = storageData[TagLen + 1] + 2 + TagLen;
                else {
                    dataLen = storageData[TagLen + 1] * 256 + storageData[TagLen + 2] + 3 + TagLen;
                }
            }
            else
                dataLen = storageData[TagLen] + 1 + TagLen;

            *certificateSize = dataLen;
            return 1; // valid
        }
    }

    return 0; // invalid
}

HLSE_RET_CODE   HLSE_EnumerateObjects(HLSE_OBJECT_TYPE objectType, HLSE_OBJECT_HANDLE* objectHandles, U16* objectHandlesLen)
{
    U8 storageData[HLSE_MAX_STORAGE_SIZE];
    U16 storageDataLen = sizeof(storageData);
    U8 certExists = 0, symKeyExists = 0, asymKeyExists = 0;
    U16 objCount = 0; // the Module always exists

    U16 lReturn;
#ifndef HLSE_IGNORE_PARAM_CHECK
    //objectHandles is NULL, then all that the function does is return (in \p *objectHandlesLen) a number of HLSE_OBJECT_HANDLE which would suffice
    // to hold the returned list.  HLSE_SW_OK is returned by the function.

    //If objectHandles is not NULL, then objectHandlesLen must contain the number of handles in the buffer objectHandles
    if (objectHandles != NULL && objectHandlesLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }

    if (objectHandlesLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // Read record # 0 and check the data to see if it's a certificate in TLV format
    lReturn = CL_FreeReadServiceData(0, storageData, &storageDataLen);
    if (lReturn == HLSE_SW_OK) {
        U16 certificateSize = 0;
        certExists = IsDataValidCertificate(storageData, storageDataLen, &certificateSize);
    }

    // If in PERSONALIZED mode (i.e. there is an ID2 data) then we assume there is a Symmetric and Assymmetric key
    {
        sCL_ID iD2Id;

        lReturn = CL_GetID((U8*)&iD2Id, sizeof(sCL_ID));
        if (lReturn == HLSE_SW_OK) {
            symKeyExists = 1;
            asymKeyExists = 1;
        }
    }
    // GP Get Status ?


    if (objectType == HLSE_MODULE) {
        objCount++;
    }
    // How to check if the KEK exists or not????
    else if (objectType == HLSE_KEK_KEY) {
        objCount++;
    }
    else if (objectType != HLSE_CERTIFICATE/* && objectType != HLSE_DATA*/) {

        if (objectType == HLSE_MODULE || objectType == HLSE_ANY_TYPE) {
            objCount++;
        }
        if (objectType == HLSE_KEK_KEY || objectType == HLSE_ANY_TYPE) {
            objCount++;
        }

        if (asymKeyExists && (objectType == HLSE_KEY_PAIR || objectType == HLSE_ANY_TYPE))
            objCount++; // public key too???
        else if (symKeyExists &&  (objectType == HLSE_SYMMETRIC_KEY || objectType == HLSE_ANY_TYPE))
            objCount++;
    }

    // read Certificate/Data objects
    if (objectType == HLSE_CERTIFICATE /*|| objectType == HLSE_DATA */|| objectType == HLSE_ANY_TYPE) {
        if (certExists) {
            objCount++;
        }
    }

    if (objectHandles == NULL) {
        *objectHandlesLen = objCount;
        return HLSE_SW_OK;
    }
    if (objectHandles != NULL && objectHandlesLen != NULL && *objectHandlesLen < objCount) {
        *objectHandlesLen = objCount;
        return HLSE_ERR_BUF_TOO_SMALL;
    }

    *objectHandlesLen = 0;

    if (objectType == HLSE_MODULE || objectType == HLSE_ANY_TYPE) {
        objectHandles[(*objectHandlesLen)++] = HLSE_CREATE_HANDLE(1, HLSE_MODULE, 0);
    }
    else if (objectType == HLSE_KEK_KEY || objectType == HLSE_ANY_TYPE) {
        objectHandles[(*objectHandlesLen)++] = HLSE_CREATE_HANDLE(1, HLSE_KEK_KEY, 0);
    }
    else if (objectType != HLSE_CERTIFICATE && objectType != HLSE_DATA) {
       if (asymKeyExists && (objectType == HLSE_KEY_PAIR || objectType == HLSE_ANY_TYPE))
           objectHandles[(*objectHandlesLen)++] = HLSE_CREATE_HANDLE(false, HLSE_KEY_PAIR, 0); // public key too???
        else if (symKeyExists && (objectType == HLSE_SYMMETRIC_KEY || objectType == HLSE_ANY_TYPE))
            objectHandles[(*objectHandlesLen)++] = HLSE_CREATE_HANDLE(false, HLSE_SYMMETRIC_KEY, 0);
    }


    // add Certificate objects
    if (objectType == HLSE_CERTIFICATE /*|| objectType == HLSE_DATA */ || objectType == HLSE_ANY_TYPE) {
        if (certExists) {
            objectHandles[(*objectHandlesLen)++] = HLSE_CREATE_HANDLE(false, HLSE_CERTIFICATE, 0);
        }
    }

    return HLSE_SW_OK;
}

HLSE_RET_CODE   HLSE_SetObjectAttribute(HLSE_OBJECT_HANDLE hObject, HLSE_ATTRIBUTE* attribute)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((attribute == NULL) || (hObject == HLSE_ANY_TYPE)) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    //***************************
    // HLSE_KEY_PAIR
    //***************************
    if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEY_PAIR) {
        // NOTE: A key pair cannot be re-generated!!!

        if (attribute->type == HLSE_ATTR_OBJECT_VALUE) {
            if (attribute->value == NULL)
                return HLSE_ERR_API_ERROR;

            return CL_SecurityStorage(attribute->value, attribute->valueLen);
        }
        else if (attribute->type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            if (attribute->value == NULL || attribute->valueLen != sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS))
                return HLSE_ERR_API_ERROR;
            {
                HLSE_KEK_WRAPPED_OBJECT_PARAMS* data;
                data = (HLSE_KEK_WRAPPED_OBJECT_PARAMS*)(attribute->value);

                return CL_SecurityStorageWithKEK(data->value, data->valueLen, data->KEK, data->KEKLen);
            }
        }
        else
            return HLSE_ERR_API_ERROR;
    }
    ////***************************
    //// HLSE_PUBLIC_KEY
    ////***************************
    //else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_PUBLIC_KEY) {
    //    if (attribute->value == NULL || attribute->valueLen == 0)
    //        return HLSE_ERR_API_ERROR;

    //    if (attribute->type == HLSE_ATTR_OBJECT_VALUE)
    //        return A71_SetEccPublicKey(HLSE_GET_OBJECT_INDEX(hObject), (U8*)(attribute->value), attribute->valueLen);
    //    else
    //        return HLSE_ERR_API_ERROR;
    //}
    //***************************
    // HLSE_SYMMETRIC_KEY
    //***************************
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_SYMMETRIC_KEY) {
        if (attribute->value == NULL)
            return HLSE_ERR_API_ERROR;

        if (attribute->type == HLSE_ATTR_OBJECT_VALUE) {
            if (attribute->value == NULL)
                return HLSE_ERR_API_ERROR;

            return CL_SecurityStorage(attribute->value, attribute->valueLen);
        }
        else if (attribute->type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            if (attribute->value == NULL || attribute->valueLen != sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS))
                return HLSE_ERR_API_ERROR;
            {
                HLSE_KEK_WRAPPED_OBJECT_PARAMS* data;
                data = (HLSE_KEK_WRAPPED_OBJECT_PARAMS*)(attribute->value);

                return CL_SecurityStorageWithKEK(data->value, data->valueLen, data->KEK, data->KEKLen);
            }
        }
        else
            return HLSE_ERR_API_ERROR;
    }
    //***************************
    // HLSE_KEK_KEY
    //***************************
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEK_KEY) {
        if (attribute->value == NULL)
            return HLSE_ERR_API_ERROR;

        if (attribute->type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            if (attribute->value == NULL || attribute->valueLen != sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS))
                return HLSE_ERR_API_ERROR;
            {
                HLSE_KEK_WRAPPED_OBJECT_PARAMS* data;
                data = (HLSE_KEK_WRAPPED_OBJECT_PARAMS*)(attribute->value);

                return CL_SetKEKValue(data->KEK, data->KEKLen, data->value, data->valueLen);
            }
        }
        else if (attribute->type == HLSE_ATTR_EXTERNAL_AUTH) {
            if (attribute->value == NULL || attribute->valueLen != 16)
                return HLSE_ERR_API_ERROR;

            return CL_ExternalAuthenticate(attribute->value, attribute->valueLen);
        }
        else
            return HLSE_ERR_API_ERROR;
    }
    //***************************
    // HLSE_CERTIFICATE
    //***************************
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_CERTIFICATE ) {
        // NOTE: Assuming the object is updated/created in either Plain Injection mode or Authentication mode only

        if (attribute->value == NULL)
            return HLSE_ERR_API_ERROR;

        // NOTE: currently allowing only one certificate with index 0
        if (HLSE_GET_OBJECT_INDEX(hObject) != 0)
            return HLSE_ERR_IDENT_IDX_RANGE;

        // Plain Injection Mode
        if (attribute->type == HLSE_ATTR_OBJECT_VALUE) {
            U16 certificateSize = 0;
            U16 remainingSize;
            U16 dataOffset = 0;
            U8 recordNum = 0;
            U16 chunkSize = 255;

            if (attribute->value == NULL)
                return HLSE_ERR_API_ERROR;

            // The Certificate data must be in TLV format
            if (!IsDataValidCertificate(attribute->value, attribute->valueLen, &certificateSize))
                return HLSE_ERR_TLV_MISSING;

            remainingSize = attribute->valueLen;
            while (remainingSize) {
                U16 lReturn;
                U16 sentLength = (remainingSize >= chunkSize ? chunkSize : remainingSize);

                lReturn = CL_UpdateServiceData(recordNum, NULL, 0, (U8*)attribute->value + dataOffset, sentLength);
                if (lReturn != SW_OK)
                    return lReturn;

                recordNum++;
                dataOffset += sentLength;
                remainingSize -= sentLength;
            }

            return SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            if (attribute->value == NULL || attribute->valueLen != sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS))
                return HLSE_ERR_API_ERROR;
            {
                U16 certificateSize = 0;
                U16 remainingSize;
                U16 dataOffset = 0;
                U8 recordNum = 0;
                U16 chunkSize = 224;
                HLSE_KEK_WRAPPED_OBJECT_PARAMS* data;
                data = (HLSE_KEK_WRAPPED_OBJECT_PARAMS*)(attribute->value);

                // The Certificate data must be in TLV format
                if (!IsDataValidCertificate(data->value, data->valueLen, &certificateSize))
                    return HLSE_ERR_TLV_MISSING;

                remainingSize = data->valueLen;
                while (remainingSize) {
                    U16 lReturn;
                    U16 sentLength = (remainingSize >= chunkSize ? chunkSize : remainingSize);

                    lReturn = CL_UpdateServiceData(recordNum, data->KEK, data->KEKLen, (U8*)data->value + dataOffset, sentLength);
                    if (lReturn != SW_OK)
                        return lReturn;

                    recordNum++;
                    dataOffset += sentLength;
                    remainingSize -= sentLength;
                }

                return SW_OK;
             }
        }
    }
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_DATA) {
        // NOTE: Assuming the object is updated/created in either Plain Injection mode or Authentication mode only

        if (attribute->value == NULL)
            return HLSE_ERR_API_ERROR;

        // NOTE: currently allowing only one certificate with index 0
        if (HLSE_GET_OBJECT_INDEX(hObject) != 0)
            return HLSE_ERR_IDENT_IDX_RANGE;

        // Plain Injection Mode
        if (attribute->type == HLSE_ATTR_OBJECT_VALUE) {
            U16 remainingSize;
            U16 dataOffset = 0;
            U8 recordNum = 0;
            U16 chunkSize = 255;

            if (attribute->value == NULL)
                return HLSE_ERR_API_ERROR;

            remainingSize = attribute->valueLen;
            while (remainingSize) {
                U16 lReturn;
                U16 sentLength = (remainingSize >= chunkSize ? chunkSize : remainingSize);

                lReturn = CL_UpdateServiceData(recordNum, NULL, 0, (U8*)attribute->value + dataOffset, sentLength);
                if (lReturn != SW_OK)
                    return lReturn;

                recordNum++;
                dataOffset += sentLength;
                remainingSize -= sentLength;
            }

            return SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            if (attribute->value == NULL || attribute->valueLen != sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS))
                return HLSE_ERR_API_ERROR;
            {
                U16 remainingSize;
                U16 dataOffset = 0;
                U8 recordNum = 0;
                U16 chunkSize = 224;
                HLSE_KEK_WRAPPED_OBJECT_PARAMS* data;
                data = (HLSE_KEK_WRAPPED_OBJECT_PARAMS*)(attribute->value);

                remainingSize = data->valueLen;
                while (remainingSize) {
                    U16 lReturn;
                    U16 sentLength = (remainingSize >= chunkSize ? chunkSize : remainingSize);

                    lReturn = CL_UpdateServiceData(recordNum, data->KEK, data->KEKLen, (U8*)data->value + dataOffset, sentLength);
                    if (lReturn != SW_OK)
                        return lReturn;

                    recordNum++;
                    dataOffset += sentLength;
                    remainingSize -= sentLength;
                }

                return SW_OK;
            }
        }
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLSE_GetObjectAttribute(HLSE_OBJECT_HANDLE hObject, HLSE_ATTRIBUTE* attribute)
{
    HLSE_RET_CODE lReturn = HLSE_SW_OK;
#ifndef HLSE_IGNORE_PARAM_CHECK
    // allow only specific type
    if (hObject == HLSE_ANY_TYPE) {
        return HLSE_ERR_API_ERROR;
    }

    if (attribute == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // { Check if user requets to obtain the length only
    if (attribute->value == NULL) {
        // return in attribute->valueLen a number of bytes which would suffice to hold the value to be returned
        if (attribute->type == HLSE_ATTR_OBJECT_TYPE) {
            attribute->valueLen = sizeof(HLSE_OBJECT_TYPE);
            return HLSE_SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_OBJECT_INDEX) {
            attribute->valueLen = sizeof(HLSE_OBJECT_INDEX);
            return HLSE_SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_MODULE_MODE) {
            attribute->valueLen = 1;
            return HLSE_SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_MODULE_CL_ID) {
            attribute->valueLen = 256 + 3;
            return HLSE_SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_VENDOR_INFO) {
            attribute->valueLen = sizeof(sCL_VendorInfo);
            return HLSE_SW_OK;
        }
        else if (attribute->type == HLSE_ATTR_MODULE_RANDOM) {
            attribute->valueLen = 16;
            return HLSE_SW_OK;
        }
        else if (((HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEY_PAIR) || (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_PUBLIC_KEY)) && (attribute->type == HLSE_ATTR_RSA_MODULUS)) {
            attribute->valueLen = sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)];
            return HLSE_SW_OK;
        }
        else if (((HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEY_PAIR) || (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_PUBLIC_KEY)) && (attribute->type == HLSE_ATTR_RSA_PUBLIC_EXPONENT)) {
            attribute->valueLen = HLSE_RSA_PUBLIC_EXPONENT_SIZE;
            return HLSE_SW_OK;
        }
        else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_CERTIFICATE /*|| HLSE_GET_OBJECT_TYPE(hObject) == HLSE_DATA*/) {
            // length will be retrieved later on GetObjectData()
        }
        else {
            // type requested not found
            return HLSE_ERR_API_ERROR;
        }
    }
    // } end section obtaining only the length


    if (attribute->type == HLSE_ATTR_OBJECT_TYPE) {
        if (attribute->valueLen >= sizeof(HLSE_OBJECT_TYPE)) {
            HLSE_OBJECT_TYPE type = HLSE_GET_OBJECT_TYPE(hObject);
            memcpy(attribute->value, &type, sizeof(HLSE_OBJECT_TYPE));
            attribute->valueLen = sizeof(HLSE_OBJECT_TYPE);
            return HLSE_SW_OK;
        }
        else {
            return HLSE_ERR_BUF_TOO_SMALL;
        }
    }
    else if (attribute->type == HLSE_ATTR_OBJECT_INDEX) {
        if (attribute->valueLen >= sizeof(HLSE_OBJECT_INDEX)) {
            HLSE_OBJECT_INDEX index = HLSE_GET_OBJECT_FULL_INDEX(hObject);
            memcpy(attribute->value, &index, sizeof(HLSE_OBJECT_INDEX));
            attribute->valueLen = sizeof(HLSE_OBJECT_INDEX);
            return HLSE_SW_OK;
        }
        else {
            return HLSE_ERR_BUF_TOO_SMALL;
        }
    }
    //else if (attribute->type == HLSE_ATTR_READ_ONLY) {
    //    if (attribute->valueLen >= sizeof(U8)) {
    //        U8 objState = ((hObject & 0x80000000) ? 1 : 0);
    //        memcpy(attribute->value, &objState, 1);
    //        attribute->valueLen = 1;
    //        return HLSE_SW_OK;
    //    }
    //    else {
    //        return HLSE_ERR_BUF_TOO_SMALL;
    //    }
    //}
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_MODULE) {
        if (attribute->type == HLSE_ATTR_MODULE_CL_ID) {
            if (attribute->valueLen < 40) {
                attribute->valueLen = 40;
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            return CL_GetID(attribute->value, attribute->valueLen);
        }
        if (attribute->type == HLSE_ATTR_MODULE_MODE) {
            U8 val;

            if (attribute->valueLen < 1) {
                attribute->valueLen = 1;
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            val = CL_IsAppletInAuthenticationMode();
            if (val)
                val = HLSE_AUTHENTICATION_MODE;
            else
                val = HLSE_DEFAULT_OR_PLAIN_MODE;

            memcpy(attribute->value, &val, 1);
            return HLSE_SW_OK;
        }
        if (attribute->type == HLSE_ATTR_VENDOR_INFO) {
            if (attribute->valueLen < sizeof(sCL_VendorInfo)) {
                attribute->valueLen = sizeof(sCL_VendorInfo);
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            attribute->valueLen = sizeof(sCL_VendorInfo);
            return CL_GetVendorInfo((sCL_VendorInfo*)attribute->value);
        }
        if (attribute->type == HLSE_ATTR_MODULE_RANDOM) {
            if (attribute->valueLen < 16) {
                attribute->valueLen = 16;
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            return CL_GetChallenge(attribute->value, (const U8)attribute->valueLen);
        }
    }
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEY_PAIR || HLSE_GET_OBJECT_TYPE(hObject) == HLSE_PUBLIC_KEY) {
        if (attribute->type == HLSE_ATTR_RSA_MODULUS) {
            if (attribute->valueLen < (sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] - 8)) {
                attribute->valueLen = sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] - 8;
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            memcpy(attribute->value, sPublicKeys[HLSE_GET_OBJECT_INDEX(hObject)] + 2, sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] - 8);
            attribute->valueLen = sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] - 8;

            return HLSE_SW_OK;
        }
        if (attribute->type == HLSE_ATTR_RSA_PUBLIC_EXPONENT) {
            if (attribute->valueLen < HLSE_RSA_PUBLIC_EXPONENT_SIZE) {
                attribute->valueLen = HLSE_RSA_PUBLIC_EXPONENT_SIZE;
                return HLSE_ERR_BUF_TOO_SMALL;
            }

            memcpy(attribute->value, sPublicKeys[HLSE_GET_OBJECT_INDEX(hObject)] + sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] - HLSE_RSA_PUBLIC_EXPONENT_SIZE, HLSE_RSA_PUBLIC_EXPONENT_SIZE);
            attribute->valueLen = HLSE_RSA_PUBLIC_EXPONENT_SIZE;

            return HLSE_SW_OK;
        }
    }
    else {
         if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_CERTIFICATE || HLSE_GET_OBJECT_TYPE(hObject) == HLSE_DATA) {
            if (attribute->type == HLSE_ATTR_OBJECT_VALUE) {
                U8 oneRecord[255];
                U16 oneRecordLen = sizeof(oneRecord);
                U8 recordNum = HLSE_GET_OBJECT_INDEX(hObject);
                // parse the data
                U16 certificateSize = 0;

                lReturn = CL_FreeReadServiceData(recordNum, oneRecord, &oneRecordLen);
                if (lReturn != HLSE_SW_OK) {
                    return lReturn;
                }

           /*     if (IsDataValidCertificate(oneRecord, oneRecordLen, &certificateSize))*/ {
                    if (attribute->value == NULL) {
                        attribute->valueLen = certificateSize;
                        return HLSE_SW_OK;
                    }
                    if (attribute->valueLen < certificateSize) {
                        attribute->valueLen = certificateSize;
                        return HLSE_ERR_BUF_TOO_SMALL;
                    }

                    // read all the records until end of certificate
                    {
                        attribute->valueLen = certificateSize;

                        if (certificateSize <= oneRecordLen) {
                            // All the data has been read in the first apdu
                            memcpy(attribute->value, oneRecord, certificateSize);
                            return HLSE_SW_OK;
                        }
                        else {
                            U16 dataOffset = oneRecordLen;

                            // copy the laready record
                            memcpy((U8*)attribute->value, oneRecord, oneRecordLen);

                            certificateSize -= oneRecordLen;

                            while (certificateSize) {
                                U16 actualBytes;

                                oneRecordLen = sizeof(oneRecord);
                                recordNum++;

                                lReturn = CL_FreeReadServiceData(recordNum, oneRecord, &oneRecordLen);
                                if (lReturn != HLSE_SW_OK) {
                                    return lReturn;
                                }

                                actualBytes = (certificateSize < oneRecordLen ? certificateSize : oneRecordLen);

                                memcpy((U8*)attribute->value + dataOffset, oneRecord, actualBytes);

                                certificateSize -= actualBytes;
                                dataOffset += actualBytes;
                            }
                        }
                    }
                }
                return HLSE_SW_OK;

            }
        }
    }

    return HLSE_ERR_API_ERROR;
}

#define HLSE_INTERNAL_KEK   0
#define HLSE_INTERNAL_ID2   1
#define HLSE_INTERNAL_TYPE   2
#define HLSE_INTERNAL_LENGTH   3
#define HLSE_INTERNAL_N   4
#define HLSE_INTERNAL_D   5
#define HLSE_INTERNAL_E   6
#define HLSE_INTERNAL_P   7
#define HLSE_INTERNAL_Q   8
#define HLSE_INTERNAL_DP  9
#define HLSE_INTERNAL_DQ   10
#define HLSE_INTERNAL_DPQ   11

static HLSE_RET_CODE HLSE_CreateRSAKey(HLSE_OBJECT_HANDLE hObject, HLSE_ATTRIBUTE* attributes, U16 attributesNum)
{
    U16 lReturn = SW_OK;
    U8 indexes[12];
    U16 keyDataFieldSize = 0;
    U16 keyLength = 0;
    U8 i;
    U8* keyData = NULL;
    U16 offset = 0;

    memset(indexes, attributesNum + 1, sizeof(indexes));

    for (i = 0; i < attributesNum; ++i) {
        if (attributes[i].value == NULL || attributes[i].valueLen == 0)
            return HLSE_ERR_API_ERROR;

        if (attributes[i].type == HLSE_ATTR_KEY_CL_ID) {
            indexes[HLSE_INTERNAL_ID2] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEK_VALUE) {
            indexes[HLSE_INTERNAL_KEK] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEY_TYPE) {
            indexes[HLSE_INTERNAL_TYPE] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEY_LENGTH) {
            indexes[HLSE_INTERNAL_LENGTH] = i;
        }
        else {
            if (attributes[i].type == HLSE_ATTR_RSA_MODULUS) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_N] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_PUBLIC_EXPONENT) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_E] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_PRIVATE_EXPONENT) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_D] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_P) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_P] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_Q) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_Q] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_DP) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_DP] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_DQ) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_DQ] = i;
            }
            else if (attributes[i].type == HLSE_ATTR_RSA_DPQ) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_DPQ] = i;
            }
        }
    }

    // no ID2 string
    if ( ((indexes[HLSE_INTERNAL_LENGTH] > attributesNum) && (indexes[HLSE_INTERNAL_ID2] > attributesNum)) || ((indexes[HLSE_INTERNAL_TYPE] > attributesNum)) )
        return HLSE_ERR_API_ERROR;
    // if the key is to be generated, no key values can be passed
    if (indexes[HLSE_INTERNAL_LENGTH] < attributesNum && keyDataFieldSize != 0)
        return HLSE_ERR_API_ERROR;

    if (indexes[HLSE_INTERNAL_ID2] < attributesNum) {
        keyData = (U8*)malloc(attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize);

        keyData[offset++] = (U8)attributes[indexes[HLSE_INTERNAL_ID2]].valueLen;
        memcpy(keyData + offset, attributes[indexes[HLSE_INTERNAL_ID2]].value, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen);
        offset += attributes[indexes[HLSE_INTERNAL_ID2]].valueLen;
        keyData[offset++] = *(U8*)(attributes[indexes[HLSE_INTERNAL_TYPE]].value);
        keyData[offset++] = HLSE_GET_OBJECT_INDEX(hObject);

        for (i = HLSE_INTERNAL_N; i < sizeof(indexes); ++i) {
            if (indexes[i] < attributesNum) {
                keyData[offset++] = (i == HLSE_INTERNAL_N ? etagRSA_N :
                    i == HLSE_INTERNAL_E ? etagRSA_E :
                    i == HLSE_INTERNAL_D ? etagRSA_D :
                    i == HLSE_INTERNAL_P ? etagRSA_CRT_P :
                    i == HLSE_INTERNAL_Q ? etagRSA_CRT_Q :
                    i == HLSE_INTERNAL_DP ? etagRSA_CRT_DP :
                    i == HLSE_INTERNAL_DQ ? etagRSA_CRT_DQ :
                    etagRSA_CRT_INVQ);
                keyData[offset++] = attributes[indexes[i]].valueLen >> 8;
                keyData[offset++] = attributes[indexes[i]].valueLen & 0xFF;
                memcpy(keyData + offset, attributes[indexes[i]].value, attributes[indexes[i]].valueLen);
                offset += attributes[indexes[i]].valueLen;
            }
        }
    }

    // Authentication mode
    if (indexes[HLSE_INTERNAL_KEK] < attributesNum) {
        if (indexes[HLSE_INTERNAL_LENGTH] < attributesNum) {
            keyLength = *(U16*)(attributes[indexes[HLSE_INTERNAL_LENGTH]].value);
            keyLength /= 8;
            lReturn = CL_GenerateKeyPairWithKEK(sPublicKeys[HLSE_GET_OBJECT_INDEX(hObject)],
                                                keyLength, *(U8*)(attributes[indexes[HLSE_INTERNAL_TYPE]].value), HLSE_GET_OBJECT_INDEX(hObject),
                                                attributes[indexes[HLSE_INTERNAL_KEK]].value, attributes[indexes[HLSE_INTERNAL_KEK]].valueLen);
            sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] = keyLength + 8;
        }
        else {
            lReturn = CL_SecurityStorageWithKEK(keyData, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize,
                attributes[indexes[HLSE_INTERNAL_KEK]].value, attributes[indexes[HLSE_INTERNAL_KEK]].valueLen);
        }
    }
    // Default or Plain mode
    else {
        if (indexes[HLSE_INTERNAL_LENGTH] < attributesNum) {
            keyLength = *(U16*)(attributes[indexes[HLSE_INTERNAL_LENGTH]].value);
            keyLength /= 8;
            lReturn = CL_GenerateKeyPair(sPublicKeys[HLSE_GET_OBJECT_INDEX(hObject)],
                                        keyLength, *(U8*)(attributes[indexes[HLSE_INTERNAL_TYPE]].value), HLSE_GET_OBJECT_INDEX(hObject));
            sPublicKeysLen[HLSE_GET_OBJECT_INDEX(hObject)] = keyLength + 8;
        }
        else {
            lReturn = CL_SecurityStorage(keyData, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize);
        }
    }

    free(keyData);

    return lReturn;
}

#define HLSE_INTERNAL_VALUE   4


static HLSE_RET_CODE HLSE_CreateSymmetricKey(HLSE_OBJECT_HANDLE hObject, HLSE_ATTRIBUTE* attributes, U16 attributesNum)
{
    U16 lReturn = SW_OK;
    U8 indexes[5];
    U16 keyDataFieldSize = 0;
    U8 i;
    U8* keyData = NULL;
    U16 offset = 0;

    memset(indexes, attributesNum + 1, sizeof(indexes));

    for (i = 0; i < attributesNum; ++i) {
        if (attributes[i].value == NULL || attributes[i].valueLen == 0)
            return HLSE_ERR_API_ERROR;

        if (attributes[i].type == HLSE_ATTR_KEY_CL_ID) {
            indexes[HLSE_INTERNAL_ID2] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEK_VALUE) {
            indexes[HLSE_INTERNAL_KEK] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEY_TYPE) {
            indexes[HLSE_INTERNAL_TYPE] = i;
        }
        else if (attributes[i].type == HLSE_ATTR_KEY_LENGTH) {
            indexes[HLSE_INTERNAL_LENGTH] = i;
        }
        else {
            if (attributes[i].type == HLSE_ATTR_OBJECT_VALUE) {
                keyDataFieldSize += (3 + attributes[i].valueLen);
                indexes[HLSE_INTERNAL_VALUE] = i;
            }
        }
    }

    // no ID2 string
    if (indexes[HLSE_INTERNAL_ID2] > attributesNum || indexes[HLSE_INTERNAL_TYPE] > attributesNum)
        return HLSE_ERR_API_ERROR;

    keyData = (U8*)malloc(attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize);

    keyData[offset++] = (U8)attributes[indexes[HLSE_INTERNAL_ID2]].valueLen;
    memcpy(keyData + offset, attributes[indexes[HLSE_INTERNAL_ID2]].value, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen);
    offset += attributes[indexes[HLSE_INTERNAL_ID2]].valueLen;
    keyData[offset++] = *(U8*)(attributes[indexes[HLSE_INTERNAL_TYPE]].value);
    keyData[offset++] = HLSE_GET_OBJECT_INDEX(hObject);

    if (indexes[HLSE_INTERNAL_VALUE] < attributesNum) {
        keyData[offset++] = *(U8*)(attributes[indexes[HLSE_INTERNAL_TYPE]].value) == e3DES ? etag3ES : etagAES;
        keyData[offset++] = attributes[indexes[HLSE_INTERNAL_VALUE]].valueLen >> 8;
        keyData[offset++] = attributes[indexes[HLSE_INTERNAL_VALUE]].valueLen & 0xFF;
        memcpy(keyData + offset, attributes[indexes[HLSE_INTERNAL_VALUE]].value, attributes[indexes[HLSE_INTERNAL_VALUE]].valueLen);
        offset += attributes[indexes[HLSE_INTERNAL_VALUE]].valueLen;
    }

    if (indexes[HLSE_INTERNAL_KEK] < attributesNum) {
        lReturn = CL_SecurityStorageWithKEK(keyData, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize,
            attributes[indexes[HLSE_INTERNAL_KEK]].value, attributes[indexes[HLSE_INTERNAL_KEK]].valueLen);
    }
    else {
        lReturn = CL_SecurityStorage(keyData, attributes[indexes[HLSE_INTERNAL_ID2]].valueLen + 3 + keyDataFieldSize);
    }

    free(keyData);

    return lReturn;
}

HLSE_RET_CODE HLSE_CreateObject(HLSE_ATTRIBUTE* attributes, U16 attributesNum, HLSE_OBJECT_HANDLE* hObject)
{
    // Sym key - create
    // Asym key - create + gen (w/o KEK)
    // certificate


    // Get the object type and index and create the handle
    HLSE_OBJECT_TYPE objType = HLSE_ANY_TYPE;
    HLSE_OBJECT_INDEX objIndex = 0;
    U16 valAttrIndex = 0;
    U8 readOnly = 0;
    HLSE_RET_CODE lReturn = HLSE_SW_OK;
    U8 i;

#ifndef HLSE_IGNORE_PARAM_CHECK
    // HLSE_ATTR_OBJECT_TYPE and HLSE_ATTR_OBJECT_INDEX must appear
    if (attributes == NULL || hObject == NULL || attributesNum < 2)
        return HLSE_ERR_API_ERROR;
#endif

    for (i = 0; i < attributesNum; ++i) {
        if (attributes[i].type == HLSE_ATTR_OBJECT_TYPE) {
            if (attributes[i].value == NULL || attributes[i].valueLen < 4)
                return HLSE_ERR_API_ERROR;

            objType = *(HLSE_OBJECT_TYPE*)(attributes[i].value);
        }
        else if (attributes[i].type == HLSE_ATTR_OBJECT_INDEX) {
            if (attributes[i].value == NULL || attributes[i].valueLen < 4)
                return HLSE_ERR_API_ERROR;

            objIndex = *(HLSE_OBJECT_INDEX*)(attributes[i].value);
        }
        //else if (attributes[i].type == HLSE_ATTR_READ_ONLY) {
        //    if (attributes[i].value == NULL || attributes[i].valueLen < 1)
        //        return HLSE_ERR_API_ERROR;

        //    readOnly = *(U8*)(attributes[i].value);
        //}
        else if (attributes[i].type == HLSE_ATTR_OBJECT_VALUE ||
                attributes[i].type == HLSE_ATTR_WRAPPED_OBJECT_VALUE) {
            valAttrIndex = i;
        }
    }

    *hObject = HLSE_CREATE_HANDLE(readOnly, objType, objIndex);

    //if (generateKeyPair) {
    //    if (attributes[valAttrIndex].value == NULL || attributes[valAttrIndex].valueLen != sizeof(HLSE_RSA_KEY_GENERATION_PARAMS)) {
    //        *hObject = 0;
    //        return HLSE_ERR_API_ERROR;
    //    }

    //    {
    //        HLSE_RSA_KEY_GENERATION_PARAMS* data = (HLSE_RSA_KEY_GENERATION_PARAMS*)attributes[valAttrIndex].value;

    //        if (data->KEKLen != 0) {
    //            lReturn = CL_GenerateKeyPairWithKEK(data->pPublicKey, data->keyLength, data->keyType, objIndex, data->KEK, data->KEKLen);
    //        }
    //        else {
    //            lReturn = CL_GenerateKeyPair(data->pPublicKey, data->keyLength, data->keyType, objIndex);
    //        }
    //    }
    //}
    if (objType == HLSE_KEY_PAIR || objType == HLSE_PUBLIC_KEY) {
        lReturn = HLSE_CreateRSAKey(*hObject, attributes, attributesNum);
    }
    else if (objType == HLSE_SYMMETRIC_KEY) {
        lReturn = HLSE_CreateSymmetricKey(*hObject, attributes, attributesNum);
    }
    else {
        lReturn = HLSE_SetObjectAttribute(*hObject, &attributes[valAttrIndex]);
    }

    if (lReturn != HLSE_SW_OK) {
        *hObject = 0;
        return lReturn;
    }

    return lReturn;
}

HLSE_RET_CODE   HLSE_EraseObject(HLSE_OBJECT_HANDLE hObject)
{
    // delete a certificate object?

    return HLSE_ERR_NOT_SUPPORTED;
}

//*******************************************************************
// Cryptographic Operations - defined in HLSECrypto.h
//*******************************************************************

HLSE_RET_CODE   HLSE_GetSupportedMechanisms(HLSE_MECHANISM_TYPE* mechanism, U16* mechanismLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (mechanismLen == NULL)
        return HLSE_ERR_API_ERROR;
#endif

    if (mechanism == NULL) {
        *mechanismLen = 21;
        return HLSE_SW_OK;
    }
    if (mechanism != NULL && mechanismLen != NULL && *mechanismLen < 21) {
        *mechanismLen = 21;
        return HLSE_ERR_BUF_TOO_SMALL;
    }

    *mechanismLen = 21;

    *mechanism++ = HLSE_SHA1;
    *mechanism++ = HLSE_SHA256;
    *mechanism++ = HLSE_AES_ECB_ENCRYPT;
    *mechanism++ = HLSE_AES_ECB_DECRYPT;
    *mechanism++ = HLSE_AES_CBC_ENCRYPT;
    *mechanism++ = HLSE_AES_CBC_DECRYPT;
    *mechanism++ = HLSE_DES_ECB_ENCRYPT;
    *mechanism++ = HLSE_DES_ECB_DECRYPT;
    *mechanism++ = HLSE_DES_CBC_ENCRYPT;
    *mechanism++ = HLSE_DES_CBC_DECRYPT;
    *mechanism++ = HLSE_DES_CBC_ISO9797_M1;
    *mechanism++ = HLSE_DES_CBC_ISO9797_M2;
    *mechanism++ = HLSE_AES_CBC_ISO9797_M1;
    *mechanism++ = HLSE_AES_CBC_ISO9797_M2;
    *mechanism++ = HLSE_RSA_KEY_GEN;
    *mechanism++ = HLSE_RSA_CRT_KEY_GEN;
    *mechanism++ = HLSE_RSA_NO_PADDING;
    *mechanism++ = HLSE_RSA_PKCS1_SHA1;
    *mechanism++ = HLSE_RSA_PKCS1_SHA256;
    *mechanism++ = HLSE_RSA_PKCS1_SHA1_PREHASH;
    *mechanism++ = HLSE_RSA_PKCS1_SHA256_PREHASH;

    return HLSE_SW_OK;
}

HLSE_RET_CODE   HLSE_GetSupportedMechanismsForObject(HLSE_OBJECT_HANDLE hObject, HLSE_MECHANISM_TYPE* mechanism, U16* mechanismLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (mechanismLen == NULL)
        return HLSE_ERR_API_ERROR;
#endif

    if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_KEY_PAIR) {
        if (mechanism == NULL) {
            *mechanismLen = 7;
            return HLSE_SW_OK;
        }
        if (mechanism != NULL && mechanismLen != NULL && *mechanismLen < 7) {
            *mechanismLen = 7;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        *mechanismLen = 7;

        *mechanism++ = HLSE_RSA_KEY_GEN;
        *mechanism++ = HLSE_RSA_CRT_KEY_GEN;
        *mechanism++ = HLSE_RSA_NO_PADDING;
        *mechanism++ = HLSE_RSA_PKCS1_SHA1;
        *mechanism++ = HLSE_RSA_PKCS1_SHA256;
        *mechanism++ = HLSE_RSA_PKCS1_SHA1_PREHASH;
        *mechanism++ = HLSE_RSA_PKCS1_SHA256_PREHASH;
    }
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_PUBLIC_KEY) {
        if (mechanism == NULL) {
            *mechanismLen = 3;
            return HLSE_SW_OK;
        }
        if (mechanism != NULL && mechanismLen != NULL && *mechanismLen < 3) {
            *mechanismLen = 3;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        *mechanismLen = 3;

        *mechanism++ = HLSE_RSA_NO_PADDING;
        *mechanism++ = HLSE_RSA_PKCS1_SHA1;
        *mechanism++ = HLSE_RSA_PKCS1_SHA256;
    }
    else if (HLSE_GET_OBJECT_TYPE(hObject) == HLSE_SYMMETRIC_KEY) {
        if (mechanism == NULL) {
            *mechanismLen = 12;
            return HLSE_SW_OK;
        }
        if (mechanism != NULL && mechanismLen != NULL && *mechanismLen < 12) {
            *mechanismLen = 12;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        *mechanismLen = 12;

        *mechanism++ = HLSE_AES_ECB_ENCRYPT;
        *mechanism++ = HLSE_AES_ECB_DECRYPT;
        *mechanism++ = HLSE_AES_CBC_ENCRYPT;
        *mechanism++ = HLSE_AES_CBC_DECRYPT;
        *mechanism++ = HLSE_DES_ECB_ENCRYPT;
        *mechanism++ = HLSE_DES_ECB_DECRYPT;
        *mechanism++ = HLSE_DES_CBC_ENCRYPT;
        *mechanism++ = HLSE_DES_CBC_DECRYPT;
        *mechanism++ = HLSE_DES_CBC_ISO9797_M1;
        *mechanism++ = HLSE_DES_CBC_ISO9797_M2;
        *mechanism++ = HLSE_AES_CBC_ISO9797_M1;
        *mechanism++ = HLSE_AES_CBC_ISO9797_M2;
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLSE_Digest(HLSE_MECHANISM_INFO* pMechanismType,
                            U8* inData, U16 inDataLen,
                            U8* outDigest, U16* outDigestLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((pMechanismType == NULL) || inData == NULL || outDigestLen == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    if (pMechanismType->mechanism == HLSE_SHA1) {
        if (outDigest == NULL) {
            *outDigestLen = 20;
            return HLSE_SW_OK;
        }
        if (outDigest != NULL && outDigestLen != NULL && *outDigestLen < 20) {
            *outDigestLen = 20;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_ComputeDigest(inData, (U16)inDataLen, outDigest, outDigestLen, eSHA1);
    }
    else if (pMechanismType->mechanism == HLSE_SHA256) {
        if (outDigest == NULL) {
            *outDigestLen = 32;
            return HLSE_SW_OK;
        }
        if (outDigest != NULL && outDigestLen != NULL && *outDigestLen < 32) {
            *outDigestLen = 32;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_ComputeDigest(inData, (U16)inDataLen, outDigest, outDigestLen, eSHA256);
    }

    return HLSE_ERR_API_ERROR;
}

//HLSE_RET_CODE   HLSE_DigestInit(HLSE_MECHANISM_INFO* pMechanismType, HLSE_CONTEXT_HANDLE* hContext)
//{
//
//}
//
//HLSE_RET_CODE   HLSE_DigestUpdate(HLSE_CONTEXT_HANDLE hContext, U8* inDataPart, U16 inDataPartLen)
//{
//
//}
//
//HLSE_RET_CODE   HLSE_DigestFinal(HLSE_CONTEXT_HANDLE hContext, U8* outDigest, U16* outDigestLen)
//{
//
//}

HLSE_RET_CODE   HLSE_Sign(HLSE_MECHANISM_INFO* pMechanismType, HLSE_OBJECT_HANDLE hObject,
                          U8* inData, U16 inDataLen,
                          U8* outSignature, U16* outSignatureLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((pMechanismType == NULL) || (inData == NULL) || (outSignatureLen == NULL)) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // RSA
    if (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256)
    {
        if (outSignature == NULL) {
            *outSignatureLen = 256;
            return HLSE_SW_OK;
        }
        if (outSignature != NULL && outSignatureLen != NULL && *outSignatureLen < 256) {
            *outSignatureLen = 256;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_AsymmetricCrypt(inData, (U16)inDataLen,
            eAsymSign,
            (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ? eRSA_NOPADDING :
             pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 :
             eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            outSignature, outSignatureLen);
    }
    else if (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256_PREHASH)
    {
        // keyLength is passed as the mechanism's parameter
        // inData assumed to be the hash
        U8 allData[512];
        U16 hashLen = (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH ? 20 : 32);
        U32 keyLen;
        U32 PSLen;
        U8  sha1OID[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
        U8  sha256OID[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20 };

        if (outSignature == NULL) {
            *outSignatureLen = 256;
            return HLSE_SW_OK;
        }
        if (outSignature != NULL && outSignatureLen != NULL && *outSignatureLen < 256) {
            *outSignatureLen = 256;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        if (inDataLen != hashLen) {
            return HLSE_ERR_HASH_COMPARE_FAILS;
        }

        if (pMechanismType->pParameter == NULL || pMechanismType->ulParameterLen != sizeof(U32)) {
            return HLSE_ERR_API_ERROR;
        }

        keyLen = *((U32*)pMechanismType->pParameter);

        allData[0] = 0x00;
        allData[1] = 0x01;

        PSLen = keyLen - 3 - (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH ? sizeof(sha1OID) : sizeof(sha256OID)) - hashLen;

        memset(&(allData[2]), 0xFF, PSLen);
        allData[2 + PSLen] = 0x00;
        if (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH) {
            memcpy(&(allData[3 + PSLen]), sha1OID, sizeof(sha1OID));
            memcpy(&(allData[3 + PSLen + sizeof(sha1OID)]), inData, hashLen);
        }
        else {
            memcpy(&(allData[3 + PSLen]), sha256OID, sizeof(sha256OID));
            memcpy(&(allData[3 + PSLen + sizeof(sha256OID)]), inData, hashLen);
        }

        return CL_AsymmetricCrypt(allData, (U16)keyLen,
            eAsymDecrypt,
            eRSA_NOPADDING,
            HLSE_GET_OBJECT_INDEX(hObject),
            outSignature, outSignatureLen);
   }
    // DES
    else if (pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M1 ||
        pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M2)
    {
        if (outSignature == NULL) {
            *outSignatureLen = 24;
            return HLSE_SW_OK;
        }
        if (outSignature != NULL && outSignatureLen != NULL && *outSignatureLen < 24) {
            *outSignatureLen = 24;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eSignMac,
            (pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M1 ? eDES_CBC_ISO9797_M1 : eDES_CBC_ISO9797_M2),
            HLSE_GET_OBJECT_INDEX(hObject),
            outSignature, outSignatureLen);
    }
    // AES
    else if (pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M1 ||
        pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M2)
    {
        if (outSignature == NULL) {
            *outSignatureLen = 16;
            return HLSE_SW_OK;
        }
        if (outSignature != NULL && outSignatureLen != NULL && *outSignatureLen < 16) {
            *outSignatureLen = 16;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eSignMac,
            (pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M1 ? eAES_CBC_ISO9797_M1 : eAES_CBC_ISO9797_M2),
            HLSE_GET_OBJECT_INDEX(hObject),
            outSignature, outSignatureLen);
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLSE_VerifySignature(HLSE_MECHANISM_INFO* pMechanismType, HLSE_OBJECT_HANDLE hObject,
                                     U8* inData, U16 inDataLen,
                                     U8* inSignature, U16 inSignatureLen)
{
    U8* allData = NULL;

#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((pMechanismType == NULL) || (inData == NULL) || (inSignature == NULL)) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // RSA
    if (pMechanismType->mechanism == HLSE_RSA_NO_PADDING)
    {
        HLSE_RET_CODE lReturn = 0;

        allData = (U8*)malloc(inDataLen + inSignatureLen);
        memcpy(allData, inData, inDataLen);
        memcpy(&allData[inDataLen], inSignature, inSignatureLen);

        lReturn = CL_AsymmetricCrypt(allData, (U16)(inDataLen + inSignatureLen),
            eAsymVerifySign,
            (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ? eRSA_NOPADDING :
                pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 :
                eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            inSignature, &inSignatureLen);

        free(allData);

        if (lReturn != HLSE_SW_OK)
            return lReturn;

        return HLSE_SW_OK;
    }
    else if (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256)
    {
        HLSE_RET_CODE lReturn = 0;
        U16 retDataLen = 512;
        U8 hash[100];
        U16 hashLen = (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? 20 : 32);

        allData = (U8*)malloc(512);

        lReturn = CL_AsymmetricCrypt(inSignature, inSignatureLen,
            eAsymEncrypt,
            eRSA_NOPADDING, //(pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 : eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            allData, &retDataLen);

        if (lReturn == HLSE_SW_OK) {
            // need to compute the hash of the data in order to compare with
            lReturn = CL_ComputeDigest(inData, inDataLen, hash, &hashLen, (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eSHA1 : eSHA256));
            // need to remove padding

            if (lReturn == HLSE_SW_OK) {
                if (allData[0] != 0x00 ||
                    allData[1] != 0x01) {
                    lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                }
                else {
                    unsigned long index = 2;
                    for (; allData[index] != 0x00 && index < retDataLen; index++) {
                        if (allData[index] != 0xFF) {
                            lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                        }
                    }

                    index++; // now points to first data byte

                    if (index < 11 || retDataLen <= hashLen) {
                        lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                    }

                    if (lReturn == HLSE_SW_OK) {
                        if (memcmp(hash, &allData[retDataLen - hashLen], hashLen))
                            lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                    }
                }
            }
        }

        free(allData);

        if (lReturn != HLSE_SW_OK)
            return lReturn;

        return HLSE_SW_OK;
    }
    else if (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256_PREHASH)
    {
        // inData is the hash of the data
        HLSE_RET_CODE lReturn = 0;
        U16 retDataLen = 512;
        U8 hash[100];
        U16 hashLen = (pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1_PREHASH ? 20 : 32);

        if (inDataLen != hashLen) {
            return HLSE_ERR_HASH_COMPARE_FAILS;
        }

        allData = (U8*)malloc(512);

        lReturn = CL_AsymmetricCrypt(inSignature, inSignatureLen,
            eAsymEncrypt,
            eRSA_NOPADDING, //(pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 : eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            allData, &retDataLen);

        if (inDataLen != hashLen) {
            lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
        }

        if (lReturn == HLSE_SW_OK) {
            // no need to compute the hash of the data
            memcpy(hash, inData, inDataLen);

            // need to remove padding
            if (allData[0] != 0x00 ||
                allData[1] != 0x01) {
                lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
            }
            else {
                unsigned long index = 2;
                for (; allData[index] != 0x00 && index < retDataLen; index++) {
                    if (allData[index] != 0xFF) {
                        lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                    }
                }

                index++; // now points to first data byte

                if (index < 11) {
                    lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                }

                if (lReturn == HLSE_SW_OK) {
                    if (memcmp(hash, &allData[retDataLen - hashLen], hashLen))
                        lReturn = HLSE_ERR_HASH_COMPARE_FAILS;
                }
            }
        }

        free(allData);

        if (lReturn != HLSE_SW_OK)
            return lReturn;

        return HLSE_SW_OK;
    }
    // DES
    else if (pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M1 ||
        pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M2)
    {
        HLSE_RET_CODE lReturn = 0;

        allData = (U8*)malloc(inDataLen + inSignatureLen);
        memcpy(allData, inData, inDataLen);
        memcpy(&allData[inDataLen], inSignature, inSignatureLen);

        lReturn = CL_SymmetricCrypt(allData, (U16)(inDataLen + inSignatureLen),
            eVerifyMac,
            (pMechanismType->mechanism == HLSE_DES_CBC_ISO9797_M1 ? eDES_CBC_ISO9797_M1 : eDES_CBC_ISO9797_M2),
            HLSE_GET_OBJECT_INDEX(hObject),
            inSignature, &inSignatureLen);

        free(allData);

        if (lReturn != HLSE_SW_OK)
            return lReturn;

        return HLSE_SW_OK;
    }
    // AES
    else if (pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M1 ||
        pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M2)
    {
        HLSE_RET_CODE lReturn = 0;

        allData = (U8*)malloc(inDataLen + inSignatureLen);
        memcpy(allData, inData, inDataLen);
        memcpy(&allData[inDataLen], inSignature, inSignatureLen);

        lReturn = CL_SymmetricCrypt(inData, (U16)inDataLen,
            eVerifyMac,
            (pMechanismType->mechanism == HLSE_AES_CBC_ISO9797_M1 ? eAES_CBC_ISO9797_M1 : eAES_CBC_ISO9797_M2),
            HLSE_GET_OBJECT_INDEX(hObject),
            inSignature, &inSignatureLen);

        free(allData);

        if (lReturn != HLSE_SW_OK)
            return lReturn;

        return HLSE_SW_OK;
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLSE_DeriveKey(HLSE_MECHANISM_INFO* pMechanismType, HLSE_OBJECT_HANDLE hObject,
                               U8* outDerivedKey, U16* outDerivedKeyLen)
{
    return HLSE_ERR_NOT_SUPPORTED;
}

HLSE_RET_CODE   HLSE_Encrypt(HLSE_MECHANISM_INFO* pMechanismType, HLSE_OBJECT_HANDLE hObject,
                             U8* inData, U16 inDataLen,
                             U8* outData, U16* outDataLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((pMechanismType == NULL) || (inData == NULL) || (outDataLen == NULL)) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // RSA
    if (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256)
    {
        if (outDataLen == NULL) {
            *outDataLen = 256;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < 256) {
            *outDataLen = 256;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_AsymmetricCrypt(inData, (U16)inDataLen,
            eAsymEncrypt,
            (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ? eRSA_NOPADDING :
                pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 :
                eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }
    // DES
    else if (pMechanismType->mechanism == HLSE_DES_ECB_ENCRYPT ||
        pMechanismType->mechanism == HLSE_DES_CBC_ENCRYPT)
    {
        if (outDataLen == NULL) {
            *outDataLen = inDataLen;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < inDataLen) {
            *outDataLen = inDataLen;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eEncrypt,
            (pMechanismType->mechanism == HLSE_DES_ECB_ENCRYPT ? eDES_ECB_NOPADDING : eDES_CBC_NOPADDING),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }
    // AES
    else if (pMechanismType->mechanism == HLSE_AES_ECB_ENCRYPT ||
        pMechanismType->mechanism == HLSE_AES_CBC_ENCRYPT)
    {
        if (outDataLen == NULL) {
            *outDataLen = inDataLen;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < inDataLen) {
            *outDataLen = inDataLen;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eEncrypt,
            (pMechanismType->mechanism == HLSE_AES_ECB_ENCRYPT ? eAES_ECB_NOPADDING : eAES_CBC_NOPADDING),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }

    return HLSE_ERR_API_ERROR;
}

HLSE_RET_CODE   HLSE_Decrypt(HLSE_MECHANISM_INFO* pMechanismType, HLSE_OBJECT_HANDLE hObject,
                             U8* inData, U16 inDataLen,
                             U8* outData, U16* outDataLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if ((pMechanismType == NULL) || (inData == NULL) || (outDataLen == NULL)) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    // RSA
    if (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ||
        pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA256)
    {
        if (outDataLen == NULL) {
            *outDataLen = 256;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < 256) {
            *outDataLen = 256;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_AsymmetricCrypt(inData, (U16)inDataLen,
            eAsymDecrypt,
            (pMechanismType->mechanism == HLSE_RSA_NO_PADDING ? eRSA_NOPADDING :
                pMechanismType->mechanism == HLSE_RSA_PKCS1_SHA1 ? eRSA_SHA1_PKCS1 :
                eRSA_SHA256_PKCS1),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }
    // DES
    else if (pMechanismType->mechanism == HLSE_DES_ECB_DECRYPT ||
        pMechanismType->mechanism == HLSE_DES_CBC_DECRYPT)
    {
        if (outDataLen == NULL) {
            *outDataLen = inDataLen;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < inDataLen) {
            *outDataLen = inDataLen;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eDecrypt,
            (pMechanismType->mechanism == HLSE_DES_ECB_DECRYPT ? eDES_ECB_NOPADDING : eDES_CBC_NOPADDING),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }
    // AES
    else if (pMechanismType->mechanism == HLSE_AES_ECB_ENCRYPT ||
        pMechanismType->mechanism == HLSE_AES_CBC_ENCRYPT)
    {
        if (outDataLen == NULL) {
            *outDataLen = inDataLen;
            return HLSE_SW_OK;
        }
        if (outData != NULL && outDataLen != NULL && *outDataLen < inDataLen) {
            *outDataLen = inDataLen;
            return HLSE_ERR_BUF_TOO_SMALL;
        }

        return CL_SymmetricCrypt(inData, (U16)inDataLen,
            eDecrypt,
            (pMechanismType->mechanism == HLSE_AES_ECB_DECRYPT ? eAES_ECB_NOPADDING : eAES_CBC_NOPADDING),
            HLSE_GET_OBJECT_INDEX(hObject),
            outData, outDataLen);
    }

    return HLSE_ERR_NOT_SUPPORTED;
}

//CK_ECDH1_DERIVE_PARAMS params;
//CK_MECHANISM    mechanism = { CKM_ECDH1_DERIVE, &params, sizeof(params) };

//*******************************************************************
// Module Operations - defined in HLSEMisc.h
//*******************************************************************

// Debug functions
HLSE_RET_CODE   HLSE_DisablePlainInjectionMode()
{
    return CL_DisablePlainInjectionMode();
}

HLSE_RET_CODE   HLSE_ResetContents()
{
    // the cached gp table no lnger reflects the actual data in the GP storage and has to be re-read
//  gMappingTableRead = 0;

    return CL_ResetContents();
}

HLSE_RET_CODE   HLSE_NormalizeECCSignature(U8 *signature, U16 signatureLen,
    U8 *normalizedSignature, U16 *normalizedSignatureLen)
{
    return HLSE_ERR_NOT_SUPPORTED;
}


//*******************************************************************
// Communication and Secure Channel - defined in HLSEComm.h
//*******************************************************************

HLSE_RET_CODE HLSE_CloseConnection(HLSE_CLOSE_CONNECTION_MODE mode)
{
    if ((mode != HLSE_CLOSE_CONNECTION_RESET) && (mode != HLSE_CLOSE_CONNECTION_NO_RESET)) {
        return HLSE_ERR_API_ERROR;
    }

    return SM_Close(NULL, (U8)mode);
}

HLSE_RET_CODE HLSE_Connect(HLSE_CONNECTION_PARAMS* params, HLSE_COMMUNICATION_STATE *commState)
{
#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2) || defined(RJCT_VCOM)
        SmCommState_t a71SmCommState;
		a71SmCommState.connType = params->connType;
        U16 lReturn;
#ifndef HLSE_IGNORE_PARAM_CHECK
        if (params == NULL || commState == NULL || params->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }
#endif
    // Clean the global memory
    memset(&sPublicKeysLen, 0, sizeof(sPublicKeysLen));
    memset(&sPublicKeys, 0, sizeof(sPublicKeys));
        //if (params->appletAIDLength)
        //    lReturn = SM_RjctConnectWithAID((const char *)params->pParameter, &a71SmCommState, params->appletAID, params->appletAIDLength, commState->atr, &(commState->atrLen));
        //else
        LOG_I("==========From wrapper========");
            lReturn = SM_RjctConnect(NULL, (const char *)params->pParameter, &a71SmCommState, commState->atr, &(commState->atrLen));
        if (lReturn != SW_OK) {
            return lReturn;
        }

        memcpy(commState, &a71SmCommState, sizeof(a71SmCommState));
        return HLSE_SW_OK;
#else
        SmCommState_t a71SmCommState;
        U16 lReturn;

#ifndef HLSE_IGNORE_PARAM_CHECK
        if (params == NULL || commState == NULL || params->pParameter == NULL) {
            return HLSE_ERR_API_ERROR;
        }
#endif
        //if (params->appletAIDLength)
        //    lReturn = SM_ConnectWithAID(&a71SmCommState, params->appletAID, params->appletAIDLength, commState->atr, &(commState->atrLen));
        //else
        lReturn = SM_Connect(NULL, &a71SmCommState, commState->atr, &(commState->atrLen));

        if (lReturn != SW_OK) {
            return lReturn;
        }

        memcpy(commState, &a71SmCommState, sizeof(a71SmCommState));
        return HLSE_SW_OK;
#endif
}

HLSE_RET_CODE HLSE_ResumeConnection(HLSE_COMMUNICATION_STATE *commState, HLSE_SECURE_CHANNEL_SESSION_STATE *smState)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (commState == NULL || smState == NULL ) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    if (smState->type != HLSE_SCP03 || smState->ulParameterLen != sizeof(HLSE_SCP03_SESSION_STATE))
        return HLSE_ERR_MEMORY;

#ifdef SECURE_CHANNEL_SUPPORTED
    return SM_ResumeConnection((SmCommState_t *)commState, (Scp03SessionState_t*)(smState->pParameter));
#else
    return HLSE_ERR_NOT_SUPPORTED;
#endif

}

HLSE_RET_CODE HLSE_SendAPDU(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (cmd == NULL || resp == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    return SM_SendAPDU(cmd, cmdLen, resp, respLen);
}

HLSE_RET_CODE HLSE_SCP_Subscribe(HLSE_SCP_SignalFunction callback, void *context)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (callback == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

#ifdef SECURE_CHANNEL_SUPPORTED
    return SCP_Subscribe((SCP_SignalFunction)callback, context);
#else
    return HLSE_ERR_NOT_SUPPORTED;
#endif

}

HLSE_RET_CODE HLSE_SMChannelAuthenticate(HLSE_SECURE_CHANNEL_ESTABLISH_PARAMS* params, HLSE_SECURE_CHANNEL_STATE* channelState)
{
#ifdef USE_SCP02
    HLSE_SECURE_CHANNEL_SCP02_ESTABLISH_PARAMS* scp02EstablishParams;
    HLSE_SCP02_CHANNEL_STATE* scp02ChannelState;
    U16 counterLen = 3;
#endif
    U16 lReturn = HLSE_ERR_API_ERROR;

#ifndef HLSE_IGNORE_PARAM_CHECK
    if (params == NULL || channelState == NULL) {
        return lReturn;
    }

    if (params->type != HLSE_SCP02 || params->pParameter == NULL || params->ulParameterLen != sizeof(HLSE_SECURE_CHANNEL_SCP02_ESTABLISH_PARAMS))
        return HLSE_ERR_MEMORY;
    if (channelState->type != HLSE_SCP02 || channelState->pParameter == NULL || channelState->ulParameterLen != sizeof(HLSE_SCP02_CHANNEL_STATE))
        return HLSE_ERR_MEMORY;
#endif

#ifdef USE_SCP02
    scp02EstablishParams = (HLSE_SECURE_CHANNEL_SCP02_ESTABLISH_PARAMS*)(params->pParameter);
    scp02ChannelState = (HLSE_SCP02_CHANNEL_STATE*)(channelState->pParameter);

    lReturn = SCP02_Authenticate(scp02EstablishParams->keyEnc, scp02EstablishParams->keyMac, scp02EstablishParams->keyDek, SCP_KEY_SIZE, scp02ChannelState->cCounter, &counterLen);

    if (lReturn != SW_OK)
        return lReturn;

    channelState->ulParameterLen = counterLen;

    return HLSE_SW_OK;
#else
    return lReturn;
#endif

}

HLSE_RET_CODE HLSE_SMChannelGetScpSessionState(HLSE_SECURE_CHANNEL_SESSION_STATE *channelState)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (channelState == NULL) {
        return HLSE_ERR_API_ERROR;
    }

    if (channelState->type != HLSE_SCP03 || channelState->pParameter == NULL || channelState->ulParameterLen != sizeof(HLSE_SCP03_SESSION_STATE))
        return HLSE_ERR_MEMORY;
#endif

    return SCP_GetScpSessionState((Scp03SessionState_t *)(channelState->pParameter));
}

HLSE_RET_CODE HLSE_SMChannelSetScpSessionState(HLSE_SECURE_CHANNEL_SESSION_STATE *channelState)
{
#ifndef HLSE_IGNORE_PARAM_CHECK
    if (channelState == NULL) {
        return HLSE_ERR_API_ERROR;
    }
#endif

    if (channelState->type != HLSE_SCP03 || channelState->pParameter == NULL || channelState->ulParameterLen != sizeof(HLSE_SCP03_SESSION_STATE))
        return HLSE_ERR_MEMORY;

    SCP_SetScpSessionState((Scp03SessionState_t *)(channelState->pParameter));

    return HLSE_SW_OK;
}

//*******************************************************************
// Helper functions
//*******************************************************************

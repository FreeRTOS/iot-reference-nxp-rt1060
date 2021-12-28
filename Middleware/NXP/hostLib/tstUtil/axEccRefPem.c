/**
 * @file axEccRefPem.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Creating a reference ECC pem file
 */
#include "axEccRefPem.h"

/**
* Create a PEM file containing a key reference.
*
* \note In case pubKeyLen is 0 , the value of the public key will be retrieved
    from the attached secure element (based on \p storageClass and \p keyIndex parameters)
*
* @param[in] storageClass Interpretation depends on attached Secure Element. In case of A71CH, either ::A71CH_SSI_KEY_PAIR (key pair)
      or ::A71CH_SSI_PUBLIC_KEY (public key)
* @param[in] keyIndex     Interpretation depends on attached Secure Element. In case of A71CH index of Secure Storage Class item
* @param[in] filepath     Filename/path of pem key file to be created.
* @param[in] pubKey       Value of public key to be used in pem key file.
* @param[in] pubKeyLen    Length of \p pubKey. In case a value of 0 is passed, the value of the public key will be retrieved
    from the attached secure element.
*
* @retval ::SW_OK Upon successful execution
*/
U16 axEccWritePemRefKey(U8 storageClass, U8 keyIndex, const char* filepath, const U8 *pubKey, U16 pubKeyLen)
{
    U16 sw;
    EC_KEY *eckey;
    BIO*    out = NULL;

    if ((eckey = EC_KEY_new()) == NULL)
    {
        printf("axEccWritePemRefKey: Unable to allocate memory for EC_KEY.\n");
        return ERR_MEMORY;
    }

    sw = axEccGenRefKey(eckey, NID_X9_62_prime256v1, storageClass, keyIndex, pubKey, pubKeyLen);
    if (sw != SW_OK)
    {
        printf("axEccWritePemRefKey: axEccGenRefKey() failed with status code 0x%04X.\n", sw);
        EC_KEY_free(eckey);
        return sw;
    }

    // ***** Write Key to file ******
    out = BIO_new(BIO_s_file());
    if (out == NULL)
    {
        printf("axEccWritePemRefKey: BIO error\n");
        EC_KEY_free(eckey);
        return ERR_FILE_SYSTEM;
    }
    if (BIO_write_filename(out, (void *)filepath) <= 0)
    {
        printf("axEccWritePemRefKey: out File error\n");
        BIO_vfree(out);
        EC_KEY_free(eckey);
        return ERR_FILE_SYSTEM;
    }
    if (!PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL))
    {
        printf("axEccWritePemRefKey: Unable to write Key\n");
        BIO_vfree(out);
        EC_KEY_free(eckey);
        return ERR_FILE_SYSTEM;
    }

    BIO_vfree(out);
    EC_KEY_free(eckey);
    return SW_OK;
}


/**
* Create an EC_KEY structure containing a key reference.
*
* \note In case pubKeyLen is 0 , the value of the public key will be retrieved
    from the attached secure element (based on \p storageClass and \p keyIndex parameters)
*
* @param[in,out] ecKey  IN: Structure allocated by caller; OUT: Key structure containing a key reference (referring to a key stored
      in a Secure Element).
* @param[in] nid        OpenSSL specific number indicating an ECC curve
* @param[in] storageClass Interpretation depends on attached Secure Element. In case of A71CH, either ::A71CH_SSI_KEY_PAIR (key pair)
      or ::A71CH_SSI_PUBLIC_KEY (public key)
* @param[in] keyIndex     Interpretation depends on attached Secure Element. In case of A71CH index of Secure Storage Class item
* @param[in] pubKey       Value of public key to be used in pem key file.
* @param[in] pubKeyLen    Length of \p pubKey. In case a value of 0 is passed, the value of the public key will be retrieved
    from the attached secure element.
*
* @retval ::SW_OK Upon successful execution
*/
U16 axEccGenRefKey(EC_KEY *eckey, int nid, U8 storageClass, U8 keyIndex, const U8 *pubKey, U16 pubKeyLen)
{
    U16 sw;
    U8 pubKeyBuf[1+2*96];
    U16 pubKeyBufLen = sizeof(pubKeyBuf);
    U8 privKey[96];
    U16 privKeyLen;
    EC_GROUP *group = NULL;
    EC_POINT *pub_key = NULL;
    int i;
    int j = 0;
    int key_field_len;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;
    BIGNUM *bn_priv = NULL;

    if (pubKeyLen != 0)
    {
        memcpy(pubKeyBuf, pubKey, pubKeyLen);
        pubKeyBufLen = pubKeyLen;
    }
    else
    {
        // printf("Fetch public key from Secure Module.\n");
        pubKeyBufLen = sizeof(pubKeyBuf);
#ifdef TGT_A70CI
        sw = SST_GetPublicKey(storageClass, pubKeyBuf, &pubKeyBufLen);
#elif defined(TGT_A70CM)
        sw = SST_Get_ECCPublicKey(storageClass, keyIndex, pubKeyBuf, &pubKeyBufLen);
#else
        if (storageClass == A71CH_SSI_PUBLIC_KEY)
        {
            sw = A71_GetEccPublicKey(keyIndex, pubKeyBuf, &pubKeyBufLen);
        }
        else if (storageClass == A71CH_SSI_KEY_PAIR)
        {
            sw = A71_GetPublicKeyEccKeyPair(keyIndex, pubKeyBuf, &pubKeyBufLen);
        }
        else
        {
            sw = ERR_API_ERROR;
        }
#endif
        if (sw != SW_OK)
        {
            printf("Fetching public key from Secure Element fails with status code: 0x%04X.\n", sw);
            return sw;
        }
    }

    /* create new ecdsa key (== EC_KEY) */
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
    {
        printf("Unable to allocate memory for EC_GROUP\n");
        return ERR_MEMORY;
    }
    if (EC_KEY_set_group(eckey, group) == 0)
    {
        printf("Unable to set group for new key\n");
        EC_GROUP_free(group);
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    key_field_len = (EC_GROUP_get_degree(group)+7)/8;
    if (key_field_len < 160/8)
    /* drop the curve */
    {
        printf("group degree > 160\n");
        return ERR_GENERAL_ERROR;
    }

    /* create key */
    if (!EC_KEY_generate_key(eckey))
    {
        printf("Unable to create ECC key\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    // Set the ID on private key and insert public key
    // BN_set_word(eckey->priv_key, keyIndex);
    privKeyLen = (U16)BN_bn2bin( EC_KEY_get0_private_key(eckey), privKey);
    privKey[privKeyLen-1] = keyIndex;
    privKey[privKeyLen-2] = storageClass;

    /* Insert Key ID in EC key (twice) */
    for (j=0; j<2; j++)
    {
        for (i=3; i<7; i++)
        {
            privKey[privKeyLen-i-(j*4)] = (U8)(EMBSE_REFKEY_ID >> 8*(i-3));
            // printf("%d.", privKeyLen-i-(j*4));
        }
    }
    /* Replace the more significant byte of the private key with:
       MSB              : 0x10
       Subsequent bytes : 0x00 */
    privKey[0] = 0x10;
    for (i=11; i<(privKeyLen); i++) { privKey[privKeyLen-i] = 0x00; }

    // Insert reference key into private key space
    bn_priv = BN_bin2bn(privKey, privKeyLen, NULL);
    if (bn_priv == NULL)
    {
        printf("axEccGenRefKey: Failed to covert private key into BN.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    if (!EC_KEY_set_private_key(eckey, bn_priv))
    {
        printf("axEccGenRefKey: Failed to set private key.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    // Insert public key
    if (pubKeyBufLen != (2*key_field_len+1))
    {
        printf("axEccGenRefKey: Error in public key length..\n");
        return ERR_GENERAL_ERROR;
    }

    // Convert coord-X to BN
    X = BN_bin2bn(&pubKeyBuf[1], key_field_len, NULL);
    if (X == NULL)
    {
        printf("axEccGenRefKey: Bignum error X-coord SE public key.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    // Convert coord-Y to BN
    Y = BN_bin2bn(&pubKeyBuf[1+key_field_len], key_field_len, NULL);
    if (Y == NULL)
    {
        printf("axEccGenRefKey: Bignum error Y-coord SE public key.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    // Create a new point object
    pub_key = EC_POINT_new(group);
    if (!EC_POINT_set_affine_coordinates_GFp(group, pub_key, X, Y, NULL))
    {
        printf("axEccGenRefKey: Error setting EC_POINT.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    if (1 != EC_KEY_set_public_key(eckey, pub_key))
    {
        printf("axEccGenRefKey: Error inserting SE public Key.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    EC_KEY_set_asn1_flag(eckey, nid);

    // Clean up memory
    BN_free(X);
    BN_free(Y);
    BN_free(bn_priv);
    EC_POINT_free(pub_key);
    EC_GROUP_free(group);

    return SW_OK;
}

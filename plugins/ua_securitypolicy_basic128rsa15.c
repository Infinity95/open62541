/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include "ua_securitypolicy_basic128rsa15.h"
#include "ua_types.h"
#include "ua_types_generated_handling.h"
#include "mbedtls\aes.h"
#include "mbedtls\md.h"
#include "mbedtls\md_internal.h"
#include "ua_util.h"
#include "mbedtls\ctr_drbg.h"
#include "mbedtls\x509.h"
#include "mbedtls\x509_crt.h"
#include "mbedtls\entropy.h"

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}

/////////////////////////////
// PolicyContext functions //
/////////////////////////////

typedef struct {
    mbedtls_ctr_drbg_context drbgContext;
    mbedtls_entropy_context entropyContext;

    mbedtls_x509_crl certificateRevocationList;
    mbedtls_x509_crt certificateTrustList;
    mbedtls_pk_context localPrivateKey;
} UA_SP_basic128rsa15_PolicyContextData;

static UA_StatusCode policyContext_init_sp_basic128rsa15(UA_Policy_SecurityContext *const securityContext,
                                                         const UA_SecurityPolicy *const securityPolicy,
                                                         UA_Logger logger,
                                                         void *const initData) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SecurityPolicy_Basic128Rsa15_initData *const policyInitData = (UA_SecurityPolicy_Basic128Rsa15_initData*)initData;

    securityContext->logger = logger;
    securityContext->securityPolicy = securityPolicy;

    securityContext->data = (UA_SP_basic128rsa15_PolicyContextData*)UA_malloc(sizeof(UA_SP_basic128rsa15_PolicyContextData));

    if(securityContext->data == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    // Initialize the PolicyContext data to sensible values
    UA_SP_basic128rsa15_PolicyContextData* data = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    mbedtls_ctr_drbg_init(&data->drbgContext);
    mbedtls_entropy_init(&data->entropyContext);

    for(size_t i = 0; i < policyInitData->entropySources.count; ++i) {
        UA_EntropySource_sp_basic128rsa15 *const source = &policyInitData->entropySources.sources[i];
        mbedtls_entropy_add_source(&data->entropyContext,
                                   source->entropyFunc,
                                   source->entropySource,
                                   source->threshold,
                                   source->strong);
    }

    mbedtls_ctr_drbg_seed(&data->drbgContext,
                          mbedtls_entropy_func,
                          &data->entropyContext,
                          policyInitData->ctrDrbg_personalizationData,
                          policyInitData->ctrDrbg_personalizationDataLen);

    mbedtls_x509_crl_init(&data->certificateRevocationList);
    mbedtls_x509_crt_init(&data->certificateTrustList);
    mbedtls_pk_init(&data->localPrivateKey);

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Initialized PolicyContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_deleteMembers_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // delete all allocated members in the data block
    UA_SP_basic128rsa15_PolicyContextData* data = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    mbedtls_ctr_drbg_free(&data->drbgContext);
    mbedtls_entropy_free(&data->entropyContext);

    mbedtls_x509_crl_free(&data->certificateRevocationList);
    mbedtls_x509_crt_free(&data->certificateTrustList);
    mbedtls_pk_free(&data->localPrivateKey);

    UA_free(securityContext->data);

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Deleted members of PolicyContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setServerPrivateKey_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                                        const UA_ByteString* const privateKey) {
    if(securityContext == NULL || privateKey == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_PolicyContextData *contextData = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    int err = mbedtls_pk_parse_key(&contextData->localPrivateKey, privateKey->data, privateKey->length, NULL, 0);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setCertificateTrustList_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                                            const UA_ByteString* const trustList) {
    if(securityContext == NULL || trustList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_PolicyContextData *contextData = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    int err = mbedtls_x509_crt_parse(&contextData->certificateTrustList, trustList->data, trustList->length);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setCertificateRevocationList_sp_basic128rsa15(UA_Policy_SecurityContext *const securityContext,
                                                                                 const UA_ByteString *const revocationList) {
    if(securityContext == NULL || revocationList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_PolicyContextData *contextData = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    int err = mbedtls_x509_crl_parse(&contextData->certificateRevocationList, revocationList->data, revocationList->length);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

/////////////////////////////////
// End PolicyContext functions //
/////////////////////////////////

//////////////////////////////
// ChannelContext functions //
//////////////////////////////

typedef struct {
    UA_ByteString localSigningKey;
    UA_ByteString localEncryptingKey;
    UA_ByteString localIv;

    UA_ByteString remoteSigningKey;
    UA_ByteString remoteEncryptingKey;
    UA_ByteString remoteIv;

    mbedtls_x509_crt remoteCertificate;
} UA_SP_basic128rsa15_ChannelContextData;

static UA_StatusCode channelContext_init_sp_basic128rsa15(UA_Channel_SecurityContext *const securityContext,
                                                          const UA_SecurityPolicy *const securityPolicy,
                                                          UA_Logger logger) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityContext->logger = logger;
    securityContext->securityPolicy = securityPolicy;

    securityContext->data = (UA_SP_basic128rsa15_ChannelContextData*)UA_malloc(sizeof(UA_SP_basic128rsa15_ChannelContextData));
    if(securityContext->data == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    // Initialize the channelcontext data here to sensible values
    UA_SP_basic128rsa15_ChannelContextData* const contextData = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    UA_ByteString_init(&contextData->localSigningKey);
    UA_ByteString_init(&contextData->localEncryptingKey);
    UA_ByteString_init(&contextData->localIv);

    UA_ByteString_init(&contextData->remoteSigningKey);
    UA_ByteString_init(&contextData->remoteEncryptingKey);
    UA_ByteString_init(&contextData->remoteIv);

    mbedtls_x509_crt_init(&contextData->remoteCertificate);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_deleteMembers_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Delete the member variables that eventually were allocated in the init method
    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    UA_ByteString_deleteMembers(&data->localSigningKey);
    UA_ByteString_deleteMembers(&data->localEncryptingKey);
    UA_ByteString_deleteMembers(&data->localIv);

    UA_ByteString_deleteMembers(&data->remoteSigningKey);
    UA_ByteString_deleteMembers(&data->remoteEncryptingKey);
    UA_ByteString_deleteMembers(&data->remoteIv);

    mbedtls_x509_crt_free(&data->remoteCertificate);

    UA_free(securityContext->data);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setLocalEncryptingKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                           const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setLocalEncryptingKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(key, &data->localEncryptingKey);
}

static UA_StatusCode channelContext_setLocalSigningKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                        const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setLocalSigningKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(key, &data->localSigningKey);
}


static UA_StatusCode channelContext_setLocalIv_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                const UA_ByteString* const iv) {
    if(securityContext == NULL || iv == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setLocalIv_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(iv, &data->localIv);
}

static UA_StatusCode channelContext_setRemoteEncryptingKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                            const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setRemoteEncryptingKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(key, &data->remoteEncryptingKey);
}

static UA_StatusCode channelContext_setRemoteSigningKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                         const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setRemoteSigningKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(key, &data->remoteSigningKey);
}

static UA_StatusCode channelContext_setRemoteIv_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                 const UA_ByteString* const iv) {
    if(securityContext == NULL || iv == NULL) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Error while calling channelContext_setRemoteIv_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    return UA_ByteString_copy(iv, &data->remoteIv);
}

static UA_StatusCode channelContext_parseRemoteCertificate_sp_basic128rsa15(UA_Channel_SecurityContext *const securityContext,
                                                                            const UA_ByteString *const remoteCertificate) {
    if(securityContext == NULL || remoteCertificate == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;
    UA_SP_basic128rsa15_ChannelContextData *const contextData = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    mbedErr |= mbedtls_x509_crt_parse(&contextData->remoteCertificate, remoteCertificate->data, remoteCertificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    mbedErr |= mbedtls_x509_time_is_future(&contextData->remoteCertificate.valid_from);
    if(mbedErr)
        return UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID;
    mbedErr |= mbedtls_x509_time_is_past(&contextData->remoteCertificate.valid_to);
    if(mbedErr)
        return UA_STATUSCODE_BADCERTIFICATETIMEINVALID;

    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(contextData->remoteCertificate.pk);

    if(rsaContext->len < securityContext->securityPolicy->asymmetricModule.minAsymmetricKeyLength ||
       rsaContext->len > securityContext->securityPolicy->asymmetricModule.maxAsymmetricKeyLength)
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;

    return UA_STATUSCODE_GOOD;
}

static size_t channelContext_getSignatureSize_sp_basic128rsa15(const UA_Channel_SecurityContext *const securityContext) {
    UA_SP_basic128rsa15_ChannelContextData *const contextData = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;
    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(contextData->remoteCertificate.pk);
    return rsaContext->len;
}

//////////////////////////////////
// End ChannelContext functions //
//////////////////////////////////

/////////////////////////////////
// Asymmetric module functions //
/////////////////////////////////

static UA_StatusCode sha1Hash(const UA_ByteString *const message,
                              UA_ByteString *const hash) {
    int mbedErr = 0;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    UA_assert(hash->length == mdInfo->size);

    mbedtls_md_context_t mdContext;
    mbedtls_md_init(&mdContext);
    mbedErr |= mbedtls_md_setup(&mdContext, mdInfo, mdInfo->type);
    mbedErr |= mbedtls_md_starts(&mdContext);
    mbedErr |= mbedtls_md_update(&mdContext, message->data, message->length);
    mbedErr |= mbedtls_md_finish(&mdContext, hash->data);
    mbedtls_md_free(&mdContext);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return retval;
}

static UA_StatusCode asym_verify_sp_basic128rsa15(const UA_ByteString* const message,
                                                  const UA_ByteString* const signature,
                                                  const void* const context) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;
    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    UA_SP_basic128rsa15_ChannelContextData *const contextData = (UA_SP_basic128rsa15_ChannelContextData*)((UA_Channel_SecurityContext*)context)->data;

    UA_ByteString hash;
    retval |= UA_ByteString_allocBuffer(&hash, mdInfo->size);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval |= sha1Hash(message, &hash);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_deleteMembers(&hash);
        return retval;
    }

    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(contextData->remoteCertificate.pk);
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V15, 0);

    mbedErr = mbedtls_pk_verify(&contextData->remoteCertificate.pk,
                                mdInfo->type,
                                hash.data,
                                hash.length,
                                signature->data,
                                signature->length);
    if(mbedErr) {
        retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_ByteString_deleteMembers(&hash);
    return retval;
}

static UA_StatusCode asym_sign_sp_basic128rsa15(const UA_ByteString* const message,
                                                const void* const context,
                                                UA_ByteString* const signature) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode asym_encrypt_sp_basic128rsa15(const UA_Policy_SecurityContext* const securityContext,
                                                   const UA_ByteString* const data) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode asym_decrypt_sp_basic128rsa15(const UA_Policy_SecurityContext* const securityContext,
                                                   UA_ByteString* const data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;

    if(securityContext == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_PolicyContextData *contextData = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;
    mbedtls_rsa_context *localPkRsaContext = mbedtls_pk_rsa(contextData->localPrivateKey);

    UA_ByteString decrypted;
    retval |= UA_ByteString_allocBuffer(&decrypted, data->length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    size_t lenDataToDecrypt = data->length;
    size_t inOffset = 0;
    size_t offset = 0;
    size_t outLength = 0;
    while(lenDataToDecrypt >= localPkRsaContext->len) {
        mbedErr = mbedtls_pk_decrypt(&contextData->localPrivateKey,
                                     data->data + inOffset,
                                     localPkRsaContext->len,
                                     decrypted.data + offset,
                                     &outLength,
                                     decrypted.length - offset,
                                     NULL,
                                     NULL);
        if(mbedErr) {
            UA_ByteString_deleteMembers(&decrypted);
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED; // TODO: is this the correct error to return here?
        }

        inOffset += localPkRsaContext->len;
        offset += outLength;
        lenDataToDecrypt -= localPkRsaContext->len;
    }

    UA_assert(lenDataToDecrypt == 0);

    memcpy(data->data, decrypted.data, outLength);
    data->length = outLength;
    UA_ByteString_deleteMembers(&decrypted);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode asym_makeThumbprint_sp_basic128rsa15(const UA_ByteString* const certificate,
                                                          UA_ByteString* const thumbprint) {
    if(certificate == NULL || thumbprint == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_UInt16 asym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                        const size_t bytesToWrite,
                                                        UA_Byte *const paddingSize,
                                                        UA_Byte *const extraPaddingSize) {
    
    if(securityPolicy == NULL || paddingSize == NULL || extraPaddingSize == NULL)
        return 0;

    UA_UInt16 plainTextBlockSize = 0; // TODO: Acquire this from somewhere?
    UA_UInt16 padding = plainTextBlockSize -
        ((bytesToWrite + securityPolicy->asymmetricModule.signingModule.signatureSize + 1) %
         plainTextBlockSize);

    *paddingSize = (UA_Byte)padding;
    *extraPaddingSize = (UA_Byte)(padding >> 8);
    
    return padding;
}

/////////////////////////////////////
// End asymmetric module functions //
/////////////////////////////////////

////////////////////////////////
// Symmetric module functions //
////////////////////////////////

/**
 * \brief Calculates a MAC using the hmacSha1 algorithm.
 *
 * \param key the key to use
 * \param in the input to create the MAC for.
 * \param out an output buffer to write the MAC to.
 *            The length must be equal to the size of the sha1 digest (20 bytes).
 */
static UA_StatusCode hmacSha1(const UA_ByteString* const key,
                              const UA_ByteString* const in,
                              UA_ByteString* const out) {
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    UA_assert(out->length >= (size_t)mdInfo->size);

    int retval = 0;

    mbedtls_md_context_t context;
    mbedtls_md_init(&context);

    retval = mbedtls_md_setup(&context, mdInfo, mdInfo->type);

    if(retval == MBEDTLS_ERR_MD_ALLOC_FAILED)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    retval = mbedtls_md_hmac_starts(&context, key->data, key->length);
    retval = mbedtls_md_hmac_update(&context, in->data, in->length);
    retval = mbedtls_md_hmac_finish(&context, out->data);
    mbedtls_md_free(&context);

    if(retval != 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    else
        return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_verify_sp_basic128rsa15(const UA_ByteString* const message,
                                                 const UA_ByteString* const signature,
                                                 const void* const context) {
    UA_Policy_SecurityContext *const policyContext = (UA_Policy_SecurityContext*)context;
    UA_SP_basic128rsa15_ChannelContextData *const data = (UA_SP_basic128rsa15_ChannelContextData*)policyContext->data;
    if(signature->length != policyContext->securityPolicy->symmetricModule.signingModule.signatureSize) {
        UA_LOG_ERROR(policyContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Signature size does not have the desired size defined by the security policy");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_ByteString mac;
    UA_ByteString_allocBuffer(&mac, signature->length);

    hmacSha1(&data->remoteSigningKey, message, &mac);

    if(!UA_ByteString_equal(&mac, signature)) {
        UA_ByteString_deleteMembers(&mac);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_ByteString_deleteMembers(&mac);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_sign_sp_basic128rsa15(const UA_ByteString* const message,
                                               const void* const context,
                                               UA_ByteString* const signature) {
    UA_SP_basic128rsa15_ChannelContextData *const data = (UA_SP_basic128rsa15_ChannelContextData*)((UA_Channel_SecurityContext*)context)->data;

    return hmacSha1(&data->localSigningKey, message, signature);
}

static UA_StatusCode sym_encrypt_sp_basic128rsa15(const UA_Channel_SecurityContext* const securityContext,
                                                  UA_ByteString* const data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_SP_basic128rsa15_ChannelContextData* const contextData = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;
    int mbedErr = 0;

    UA_assert(contextData->localIv.length == securityContext->securityPolicy->symmetricModule.encryptingBlockSize);

    if(data->length % contextData->localEncryptingKey.length != 0) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Length of data to encrypt is not a multiple of the encryptingKey length."
                     "Padding might not have been calculated appropriatley.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mbedtls_aes_context aesContext;

    mbedErr = mbedtls_aes_setkey_enc(&aesContext,
                                     contextData->localEncryptingKey.data,
                                     contextData->localEncryptingKey.length * 8); // *8 because we need bits here
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString encrypted;
    retval = UA_ByteString_allocBuffer(&encrypted, data->length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_ByteString ivCopy;
    retval = UA_ByteString_copy(&contextData->localIv, &ivCopy);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    mbedErr = mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_ENCRYPT, data->length, ivCopy.data, data->data, encrypted.data);
    if(mbedErr) {
        UA_ByteString_deleteMembers(&ivCopy);
        UA_ByteString_deleteMembers(&encrypted);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Copy encrypted back into data buffer
    memcpy(data->data, encrypted.data, data->length);

    UA_ByteString_deleteMembers(&ivCopy);
    UA_ByteString_deleteMembers(&encrypted);

    return retval;
}

static UA_StatusCode sym_decrypt_sp_basic128rsa15(const UA_Channel_SecurityContext* const securityContext,
                                                  UA_ByteString* const data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_SP_basic128rsa15_ChannelContextData* const contextData = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;
    int mbedErr = 0;

    UA_assert(contextData->remoteIv.length == securityContext->securityPolicy->symmetricModule.encryptingBlockSize);

    if(data->length % securityContext->securityPolicy->symmetricModule.encryptingBlockSize != 0) {
        UA_LOG_ERROR(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Length of data to decrypt is not a multiple of the encryptingBlock size.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mbedtls_aes_context aesContext;

    mbedErr = mbedtls_aes_setkey_dec(&aesContext,
                                     contextData->remoteEncryptingKey.data,
                                     contextData->remoteEncryptingKey.length * 8); // *8 because we need bits here
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString decrypted;
    retval = UA_ByteString_allocBuffer(&decrypted, data->length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_ByteString ivCopy;
    retval = UA_ByteString_copy(&contextData->remoteIv, &ivCopy);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    mbedErr = mbedtls_aes_crypt_cbc(&aesContext, MBEDTLS_AES_DECRYPT, data->length, ivCopy.data, data->data, decrypted.data);
    if(mbedErr) {
        UA_ByteString_deleteMembers(&ivCopy);
        UA_ByteString_deleteMembers(&decrypted);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Copy decrypted back into data buffer
    memcpy(data->data, decrypted.data, data->length);

    UA_ByteString_deleteMembers(&ivCopy);
    UA_ByteString_deleteMembers(&decrypted);

    return retval;
}

static void swapBuffers(UA_ByteString *const bufA, UA_ByteString *const bufB) {
    UA_ByteString tmp = *bufA;
    *bufA = *bufB;
    *bufB = tmp;
}

static UA_StatusCode sym_generateKey_sp_basic128rsa15(const UA_ByteString* const secret,
                                                      const UA_ByteString* const seed,
                                                      UA_ByteString* const out) {
    UA_StatusCode retval = 0;

    size_t hashLen = 0;
    {
        const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        hashLen = mdInfo->size;
    }

    UA_ByteString A_and_seed;
    UA_ByteString_allocBuffer(&A_and_seed, hashLen + seed->length);
    memcpy(A_and_seed.data + hashLen, seed->data, seed->length);

    UA_ByteString ANext_and_seed;
    UA_ByteString_allocBuffer(&ANext_and_seed, hashLen + seed->length);
    memcpy(ANext_and_seed.data + hashLen, seed->data, seed->length);

    UA_ByteString A = {
        hashLen,
        A_and_seed.data
    };

    UA_ByteString ANext = {
        hashLen,
        ANext_and_seed.data
    };

    hmacSha1(secret, seed, &A);

    for(size_t offset = 0; offset < out->length; offset += hashLen) {
        UA_ByteString outSegment = {
            hashLen,
            out->data + offset
        };
        retval |= hmacSha1(secret, &A_and_seed, &outSegment);
        retval |= hmacSha1(secret, &A, &ANext);

        if(retval != UA_STATUSCODE_GOOD) {
            UA_ByteString_deleteMembers(&A_and_seed);
            UA_ByteString_deleteMembers(&ANext_and_seed);
            return retval;
        }

        swapBuffers(&ANext_and_seed, &A_and_seed);
        swapBuffers(&ANext, &A);
    }

    UA_ByteString_deleteMembers(&A_and_seed);
    UA_ByteString_deleteMembers(&ANext_and_seed);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_generateNonce_sp_basic128rsa15(const UA_SecurityPolicy* const securityPolicy,
                                                        UA_ByteString* const out) {
    UA_assert(securityPolicy->symmetricModule.encryptingKeyLength == out->length);

    if(mbedtls_ctr_drbg_random(&((UA_SP_basic128rsa15_PolicyContextData*)securityPolicy->context.data)->drbgContext,
                               out->data,
                               securityPolicy->symmetricModule.encryptingKeyLength)
       != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_UInt16 sym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                       const size_t bytesToWrite,
                                                       UA_Byte *const paddingSize,
                                                       UA_Byte *const extraPaddingSize) {
    
    if(securityPolicy == NULL || paddingSize == NULL || extraPaddingSize == NULL)
        return 0;

    UA_UInt16 padding = (UA_UInt16)(securityPolicy->symmetricModule.encryptingBlockSize -
        ((bytesToWrite + securityPolicy->symmetricModule.signingModule.signatureSize + 1) %
         securityPolicy->symmetricModule.encryptingBlockSize));

    *paddingSize = (UA_Byte)padding;
    *extraPaddingSize = (UA_Byte)(padding >> 8);
    
    return padding;
}

////////////////////////////////////
// End symmetric module functions //
////////////////////////////////////

///////////////////////////////
// Security policy functions //
///////////////////////////////
static UA_StatusCode verifyCertificate_sp_basic128rsa15(const UA_Policy_SecurityContext *const policyContext,
                                                        const UA_Channel_SecurityContext *const channelContext) {
    UA_SP_basic128rsa15_PolicyContextData *policyContextData = (UA_SP_basic128rsa15_PolicyContextData*)policyContext->data;
    UA_SP_basic128rsa15_ChannelContextData *channelContextData = (UA_SP_basic128rsa15_ChannelContextData*)channelContext->data;
    int mbedErr = 0;

    mbedtls_x509_crt_profile crtProfile = {
        MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
        0xFFFFFF,
        0x000000,
        policyContext->securityPolicy->asymmetricModule.minAsymmetricKeyLength * 8 // in bits
    }; // TODO: remove magic numbers

    int flags = 0;
    mbedErr |= mbedtls_x509_crt_verify_with_profile(&channelContextData->remoteCertificate,
                                                    &policyContextData->certificateTrustList,
                                                    &policyContextData->certificateRevocationList,
                                                    &crtProfile,
                                                    NULL,
                                                    &flags,
                                                    NULL,
                                                    NULL);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode deleteMembers_sp_basic128rsa15(UA_SecurityPolicy* const securityPolicy) {
    if(securityPolicy == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return securityPolicy->context.deleteMembers(&securityPolicy->context);
}


static UA_StatusCode init_sp_basic128rsa15(UA_SecurityPolicy* const securityPolicy, UA_Logger logger, void *const initData) {
    if(securityPolicy == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityPolicy->logger = logger;

    // use defaults.
    if(initData == NULL) {
        UA_SecurityPolicy_Basic128Rsa15_initData defaultInitData = {
            NULL,
            0
        };
        
        return securityPolicy->context.init(&securityPolicy->context, securityPolicy, logger, &defaultInitData);
    }

    return securityPolicy->context.init(&securityPolicy->context, securityPolicy, logger, initData);
}

static UA_StatusCode makeChannelContext_sp_basic128rsa15(const UA_SecurityPolicy* const securityPolicy, UA_Channel_SecurityContext** const pp_SecurityContext) {
    if(securityPolicy == NULL || pp_SecurityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    *pp_SecurityContext = (UA_Channel_SecurityContext*)UA_malloc(sizeof(UA_Channel_SecurityContext));
    memcpy(*pp_SecurityContext, &securityPolicy->channelContextPrototype, sizeof(UA_Channel_SecurityContext));

    return UA_STATUSCODE_GOOD;
}

///////////////////////////////////
// End security policy functions //
///////////////////////////////////

UA_EXPORT UA_SecurityPolicy UA_SecurityPolicy_Basic128Rsa15 = {
    /* The policy uri that identifies the implemented algorithms */
    UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"), // .policyUri

    verifyCertificate_sp_basic128rsa15, // .verifyCertificate

                               /* Asymmetric module */
    { // .asymmetricModule
        asym_encrypt_sp_basic128rsa15, // .encrypt
        asym_decrypt_sp_basic128rsa15, // .decrypt
        asym_makeThumbprint_sp_basic128rsa15, // .makeThumbprint
        asym_calculatePadding_sp_basic128rsa15, // .calculatePadding

        128, // .minAsymmetricKeyLength
        256, // .maxAsymmetricKeyLength
        20, // .thumbprintLength

            /* Asymmetric signing module */
        {
            asym_verify_sp_basic128rsa15, // .verify
            asym_sign_sp_basic128rsa15, // .sign
            0 // .signatureSize // size_t signatureSize; in bytes .... Not applicable since dependant on rsa key length
        }
    },

    /* Symmetric module */
    { // .symmetricModule
        sym_encrypt_sp_basic128rsa15, // .encrypt
        sym_decrypt_sp_basic128rsa15, // .decrypt
        sym_generateKey_sp_basic128rsa15, // .generateKey
        sym_generateNonce_sp_basic128rsa15, // .generateNonce 
        sym_calculatePadding_sp_basic128rsa15, // .calculatePadding

                                      /* Symmetric signing module */
        { // .signingModule
            sym_verify_sp_basic128rsa15, // .verify
            sym_sign_sp_basic128rsa15, // .sign
            20 // .signatureSize // size_t signatureSize; in bytes
        },

    16, // .signingKeyLength
    16, // .encryptingKeyLength
    16 // .encryptingBlockSize
    },

    { // .context
        policyContext_init_sp_basic128rsa15, // .init
        policyContext_deleteMembers_sp_basic128rsa15, // .deleteMembers
        policyContext_setServerPrivateKey_sp_basic128rsa15, // .setServerPrivateKey
        policyContext_setCertificateTrustList_sp_basic128rsa15, // .setCertificateTrustList
        policyContext_setCertificateRevocationList_sp_basic128rsa15, // .setCertificateRevocationList

        NULL, // .data
        NULL // .logger
    },

    deleteMembers_sp_basic128rsa15, // .deleteMembers
    init_sp_basic128rsa15, // .init

                  /* Channel context prototype */
    { // .channelContextPrototype
        channelContext_init_sp_basic128rsa15,  // .init
        channelContext_deleteMembers_sp_basic128rsa15, // .deleteMembers

        channelContext_setLocalEncryptingKey_sp_basic128rsa15, // .setLocalEncryptingKey
        channelContext_setLocalSigningKey_sp_basic128rsa15, // .setLocalSigningKey
        channelContext_setLocalIv_sp_basic128rsa15, // .setLocalIv

        channelContext_setRemoteEncryptingKey_sp_basic128rsa15, // .setRemoteEncryptingKey
        channelContext_setRemoteSigningKey_sp_basic128rsa15, // .setRemoteSigningKey
        channelContext_setRemoteIv_sp_basic128rsa15, // .setRemoteIv

        channelContext_parseRemoteCertificate_sp_basic128rsa15, // .parseRemoteCertificate

        channelContext_getSignatureSize_sp_basic128rsa15,

        NULL, // .logger
        NULL // .data
    },

    makeChannelContext_sp_basic128rsa15, // .makeChannelContext
    NULL // .logger
};

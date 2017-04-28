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
#include "mbedtls\error.h"

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}

#define UA_SECURITYPOLICY_BASIC128RSA15_RSAPADDING_LEN 11

///////////////////////////////
// EndpointContext functions //
///////////////////////////////

typedef struct {
    mbedtls_ctr_drbg_context drbgContext;
    mbedtls_entropy_context entropyContext;

    mbedtls_x509_crl certificateRevocationList;
    mbedtls_x509_crt certificateTrustList;
    mbedtls_pk_context localPrivateKey;
} UA_SP_basic128rsa15_EndpointContextData;

static UA_StatusCode
endpointContext_init_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                      const void *const initData,
                                      void **const pp_contextData) {
    if(securityPolicy == NULL || initData == NULL || pp_contextData == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SecurityPolicy_Basic128Rsa15_initData *const policyInitData =
        (UA_SecurityPolicy_Basic128Rsa15_initData*)initData;

    *pp_contextData = UA_malloc(sizeof(UA_SP_basic128rsa15_EndpointContextData));

    if(*pp_contextData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    // Initialize the PolicyContext data to sensible values
    UA_SP_basic128rsa15_EndpointContextData* data = (UA_SP_basic128rsa15_EndpointContextData*)*pp_contextData;

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

    UA_LOG_DEBUG(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Initialized PolicyContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
endpointContext_deleteMembers_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                               void *const securityContext) {
    if(securityContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    // delete all allocated members in the data block
    UA_SP_basic128rsa15_EndpointContextData *const data = (UA_SP_basic128rsa15_EndpointContextData*)securityContext;

    mbedtls_ctr_drbg_free(&data->drbgContext);
    mbedtls_entropy_free(&data->entropyContext);

    mbedtls_x509_crl_free(&data->certificateRevocationList);
    mbedtls_x509_crt_free(&data->certificateTrustList);
    mbedtls_pk_free(&data->localPrivateKey);

    UA_free(securityContext);

    UA_LOG_DEBUG(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Deleted members of EndpointContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
endpointContext_setServerPrivateKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                     const UA_ByteString* const privateKey,
                                                     void *const endpointContext) {
    if(securityPolicy == NULL || privateKey == NULL || endpointContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;

    int err = mbedtls_pk_parse_key(&contextData->localPrivateKey,
                                   privateKey->data,
                                   privateKey->length,
                                   NULL,
                                   0);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
endpointContext_setCertificateTrustList_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                         const UA_ByteString* const trustList,
                                                         void *const endpointContext) {
    if(securityPolicy == NULL || trustList == NULL || endpointContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;

    int err = mbedtls_x509_crt_parse(&contextData->certificateTrustList,
                                     trustList->data,
                                     trustList->length);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
endpointContext_setCertificateRevocationList_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                              const UA_ByteString *const revocationList,
                                                              void *const endpointContext) {
    if(securityPolicy == NULL || revocationList == NULL, endpointContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;

    int err = mbedtls_x509_crl_parse(&contextData->certificateRevocationList,
                                     revocationList->data,
                                     revocationList->length);
    if(err) // TODO: more precise error handling?
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

static size_t
endpointContext_getLocalAsymSignatureSize_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                           const void *const endpointContext) {
    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;

    mbedtls_rsa_context *const rsaContext = mbedtls_pk_rsa(contextData->localPrivateKey);
    return rsaContext->len;
}

/////////////////////////////////
// End PolicyContext functions //
/////////////////////////////////

//////////////////////////////
// ChannelContext functions //
//////////////////////////////

typedef struct {
    UA_ByteString localSymSigningKey;
    UA_ByteString localSymEncryptingKey;
    UA_ByteString localSymIv;

    UA_ByteString remoteSymSigningKey;
    UA_ByteString remoteSymEncryptingKey;
    UA_ByteString remoteSymIv;

    mbedtls_x509_crt remoteCertificate;
} UA_SP_basic128rsa15_ChannelContextData;

/**
 * \brief Verifies the certificate using the trust list and revocation list in the policy context.
 *
 * \param policyContext the policy context that contains the revocation and trust lists.
 * \param channelContext the channel context that contains the already parsed certificate.
 */
static UA_StatusCode
verifyCertificate_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                   const void *const endpointContext,
                                   const void *const channelContext) {

    if(securityPolicy == NULL || endpointContext == NULL || channelContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_EndpointContextData *const endpointContextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;
    UA_SP_basic128rsa15_ChannelContextData *const channelContextData =
        (UA_SP_basic128rsa15_ChannelContextData*)channelContext;
    int mbedErr = 0;

    mbedtls_x509_crt_profile crtProfile = {
        MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
        0xFFFFFF,
        0x000000,
        securityPolicy->asymmetricModule.minAsymmetricKeyLength * 8 // in bits
    }; // TODO: remove magic numbers

    int flags = 0;
    mbedErr |= mbedtls_x509_crt_verify_with_profile(&channelContextData->remoteCertificate,
                                                    &endpointContextData->certificateTrustList,
                                                    &endpointContextData->certificateRevocationList,
                                                    &crtProfile,
                                                    NULL,
                                                    &flags,
                                                    NULL,
                                                    NULL);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parseRemoteCertificate_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                        const UA_ByteString *const remoteCertificate,
                                        void *const contextData) {
    if(securityPolicy == NULL || remoteCertificate == NULL || contextData == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;
    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    mbedErr |= mbedtls_x509_crt_parse(&data->remoteCertificate, remoteCertificate->data, remoteCertificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    mbedErr |= mbedtls_x509_time_is_future(&data->remoteCertificate.valid_from);
    if(mbedErr)
        return UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID;
    mbedErr |= mbedtls_x509_time_is_past(&data->remoteCertificate.valid_to);
    if(mbedErr)
        return UA_STATUSCODE_BADCERTIFICATETIMEINVALID;

    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(data->remoteCertificate.pk);

    if(rsaContext->len < securityPolicy->asymmetricModule.minAsymmetricKeyLength ||
       rsaContext->len > securityPolicy->asymmetricModule.maxAsymmetricKeyLength)
        return UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_deleteMembers_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                              void *const contextData);

static UA_StatusCode
channelContext_init_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                     const void *const endpointContext,
                                     const UA_ByteString *remoteCertificate,
                                     void **const pp_contextData) {

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(securityPolicy == NULL || endpointContext == NULL ||
       remoteCertificate == NULL || pp_contextData == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    *pp_contextData = UA_malloc(sizeof(UA_SP_basic128rsa15_ChannelContextData));
    if(*pp_contextData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    UA_SP_basic128rsa15_ChannelContextData* const contextData =
        (UA_SP_basic128rsa15_ChannelContextData*)*pp_contextData;

    UA_ByteString_init(&contextData->localSymSigningKey);
    UA_ByteString_init(&contextData->localSymEncryptingKey);
    UA_ByteString_init(&contextData->localSymIv);

    UA_ByteString_init(&contextData->remoteSymSigningKey);
    UA_ByteString_init(&contextData->remoteSymEncryptingKey);
    UA_ByteString_init(&contextData->remoteSymIv);

    mbedtls_x509_crt_init(&contextData->remoteCertificate);

    // TODO: this can be optimized so that we dont allocate memory before parsing the certificate
    retval |= parseRemoteCertificate_sp_basic128rsa15(securityPolicy,
                                                      remoteCertificate,
                                                      *pp_contextData);
    if(retval != UA_STATUSCODE_GOOD) {
        channelContext_deleteMembers_sp_basic128rsa15(securityPolicy,
                                                      *pp_contextData);
        *pp_contextData = NULL;
        return retval;
    }

    retval |= verifyCertificate_sp_basic128rsa15(securityPolicy,
                                                 endpointContext,
                                                 *pp_contextData);
    if(retval != UA_STATUSCODE_GOOD) {
        channelContext_deleteMembers_sp_basic128rsa15(securityPolicy,
                                                      *pp_contextData);
        *pp_contextData = NULL;
        return retval;
    }

    return retval;
}

static UA_StatusCode
channelContext_deleteMembers_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                              void *const contextData) {
    if(securityPolicy == NULL || contextData == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Delete the member variables that eventually were allocated in the init method
    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    UA_ByteString_deleteMembers(&data->localSymSigningKey);
    UA_ByteString_deleteMembers(&data->localSymEncryptingKey);
    UA_ByteString_deleteMembers(&data->localSymIv);

    UA_ByteString_deleteMembers(&data->remoteSymSigningKey);
    UA_ByteString_deleteMembers(&data->remoteSymEncryptingKey);
    UA_ByteString_deleteMembers(&data->remoteSymIv);

    mbedtls_x509_crt_free(&data->remoteCertificate);

    UA_free(data);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_setLocalSymEncryptingKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                         const UA_ByteString *const key,
                                                         void *const contextData) {
    if(securityPolicy == NULL || key == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setLocalEncryptingKey_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(key, &data->localSymEncryptingKey);
}

static UA_StatusCode
channelContext_setLocalSymSigningKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                      const UA_ByteString *const key,
                                                      void *const contextData) {
    if(securityPolicy == NULL || key == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setLocalSigningKey_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(key, &data->localSymSigningKey);
}


static UA_StatusCode
channelContext_setLocalSymIv_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                              const UA_ByteString *const iv,
                                              void *const contextData) {
    if(securityPolicy == NULL || iv == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setLocalIv_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(iv, &data->localSymIv);
}

static UA_StatusCode
channelContext_setRemoteSymEncryptingKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                          const UA_ByteString *const key,
                                                          void *const contextData) {
    if(securityPolicy == NULL || key == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setRemoteEncryptingKey_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(key, &data->remoteSymEncryptingKey);
}

static UA_StatusCode
channelContext_setRemoteSymSigningKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                       const UA_ByteString *const key,
                                                       void *const contextData) {
    if(securityPolicy == NULL || key == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setRemoteSigningKey_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(key, &data->remoteSymSigningKey);
}

static UA_StatusCode
channelContext_setRemoteSymIv_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                               const UA_ByteString* const iv,
                                               void *const contextData) {
    if(securityPolicy == NULL || iv == NULL || contextData == NULL) {
        fprintf(stderr,
                "Error while calling channelContext_setRemoteIv_sp_basic128rsa15."
                "Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    return UA_ByteString_copy(iv, &data->remoteSymIv);
}

static UA_StatusCode
channelContext_compareCertificate_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                   const void *const channelContext,
                                                   const UA_ByteString *const certificate) {

    if(securityPolicy == NULL || certificate == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    int mbedErr = 0;

    mbedtls_x509_crt cert;

    mbedErr |= mbedtls_x509_crt_parse(&cert, certificate->data, certificate->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    
    const UA_SP_basic128rsa15_ChannelContextData *const data =
        (const UA_SP_basic128rsa15_ChannelContextData*)channelContext;
    
    if(cert.raw.len != data->remoteCertificate.raw.len)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    if(memcmp(cert.raw.p, data->remoteCertificate.raw.p, cert.raw.len) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return UA_STATUSCODE_GOOD;
}

static size_t
channelContext_getRemoteAsymSignatureSize_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                           const void *const contextData) {
    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    mbedtls_rsa_context *const rsaContext = mbedtls_pk_rsa(data->remoteCertificate.pk);

    return rsaContext->len;
}

static size_t
channelContext_getRemoteAsymPlainTextBlockSize_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                                const void *const contextData) {
    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)contextData;

    mbedtls_rsa_context *const rsaContext = mbedtls_pk_rsa(data->remoteCertificate.pk);

    return rsaContext->len - UA_SECURITYPOLICY_BASIC128RSA15_RSAPADDING_LEN;
}

static size_t
channelContext_getRemoteAsymEncryptionBufferLengthOverhead_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                                                            const void *const contextData,
                                                                            const size_t maxEncryptionLength) {
    const size_t maxNumberOfBlocks =
        maxEncryptionLength /
        channelContext_getRemoteAsymPlainTextBlockSize_sp_basic128rsa15(securityPolicy,
                                                                        contextData);
    return maxNumberOfBlocks * UA_SECURITYPOLICY_BASIC128RSA15_RSAPADDING_LEN;
}

//////////////////////////////////
// End ChannelContext functions //
//////////////////////////////////

/////////////////////////////////
// Asymmetric module functions //
/////////////////////////////////

static UA_StatusCode
sha1Hash(const UA_ByteString *const message,
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

static UA_StatusCode
asym_verify_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                             const void *const context,
                             const UA_ByteString* const message,
                             const UA_ByteString* const signature) {

    if(securityPolicy == NULL || message == NULL || signature == NULL || context == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;
    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    UA_SP_basic128rsa15_ChannelContextData *const contextData =
        (UA_SP_basic128rsa15_ChannelContextData*)context;

    UA_ByteString hash;
    retval |= UA_ByteString_allocBuffer(&hash, mdInfo->size);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval |= sha1Hash(message, &hash);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_deleteMembers(&hash);
        return retval;
    }

    mbedtls_rsa_context *const rsaContext = mbedtls_pk_rsa(contextData->remoteCertificate.pk);
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V15, 0);

    mbedErr = mbedtls_pk_verify(&contextData->remoteCertificate.pk,
                                mdInfo->type,
                                hash.data,
                                hash.length,
                                signature->data,
                                signature->length);
    if(mbedErr)
        retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    UA_ByteString_deleteMembers(&hash);
    return retval;
}

static UA_StatusCode
asym_sign_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                           const void *const context,
                           const UA_ByteString* const message,
                           UA_ByteString* const signature) {

    if(securityPolicy == NULL || message == NULL || context == NULL || signature == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;

    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)context;

    UA_ByteString hash;
    retval |= UA_ByteString_allocBuffer(&hash, mdInfo->size);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval |= sha1Hash(message, &hash);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_deleteMembers(&hash);
        return retval;
    }

    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(contextData->localPrivateKey);
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V15, 0);

    size_t sigLen = 0;
    mbedErr |= mbedtls_pk_sign(&contextData->localPrivateKey,
                               mdInfo->type,
                               hash.data,
                               hash.length,
                               signature->data,
                               &sigLen,
                               mbedtls_ctr_drbg_random,
                               &contextData->drbgContext);
    if(mbedErr)
        retval = UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString_deleteMembers(&hash);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
asym_encrypt_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                              const void *const endpointContext,
                              const void *const channelContext,
                              const UA_ByteString *const data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;

    if(securityPolicy == NULL || endpointContext == NULL || channelContext == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    const size_t plainTextBlockSize =
        securityPolicy->channelContext.getRemoteAsymPlainTextBlockSize(securityPolicy,
                                                                       channelContext);

    if(data->length % plainTextBlockSize != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_ChannelContextData *const channelContextData =
        (UA_SP_basic128rsa15_ChannelContextData*)channelContext;
    UA_SP_basic128rsa15_EndpointContextData *const endpointContextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;
    mbedtls_rsa_context *const remoteRsaContext =
        mbedtls_pk_rsa(channelContextData->remoteCertificate.pk);

    mbedtls_rsa_set_padding(remoteRsaContext, MBEDTLS_RSA_PKCS_V15, 0);

    UA_ByteString encrypted;
    const size_t bufferOverhead =
        securityPolicy->channelContext.getRemoteAsymEncryptionBufferLengthOverhead(securityPolicy,
                                                                                   channelContext,
                                                                                   data->length);
    retval |= UA_ByteString_allocBuffer(&encrypted, data->length + bufferOverhead);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    size_t lenDataToEncrypt = data->length;
    size_t inOffset = 0;
    size_t offset = 0;
    size_t outLength = 0;
    while(lenDataToEncrypt >= plainTextBlockSize) {
        mbedErr = mbedtls_pk_encrypt(&channelContextData->remoteCertificate.pk,
                                     data->data + inOffset,
                                     plainTextBlockSize,
                                     encrypted.data + offset,
                                     &outLength,
                                     encrypted.length - offset,
                                     mbedtls_ctr_drbg_random,
                                     &endpointContextData->drbgContext);
        if(mbedErr) {
            UA_ByteString_deleteMembers(&encrypted);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        inOffset += plainTextBlockSize;
        offset += outLength;
        lenDataToEncrypt -= plainTextBlockSize;
    }

    memcpy(data->data, encrypted.data, offset);
    UA_ByteString_deleteMembers(&encrypted);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
asym_decrypt_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                              const void *const endpointContext,
                              UA_ByteString *const data) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    int mbedErr = 0;

    if(securityPolicy == NULL || endpointContext == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_SP_basic128rsa15_EndpointContextData *const contextData =
        (UA_SP_basic128rsa15_EndpointContextData*)endpointContext;
    mbedtls_rsa_context *const localPkRsaContext = mbedtls_pk_rsa(contextData->localPrivateKey);

    if(data->length % localPkRsaContext->len != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

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

    memcpy(data->data, decrypted.data, offset);
    data->length = offset;
    UA_ByteString_deleteMembers(&decrypted);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
asym_makeThumbprint_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                     const UA_ByteString* const certificate,
                                     UA_ByteString* const thumbprint) {
    if(securityPolicy == NULL || certificate == NULL || thumbprint == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    return sha1Hash(certificate, thumbprint);
}

static UA_UInt16
asym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                       const void *const channelContext,
                                       const void *const endpointContext,
                                       const size_t bytesToWrite,
                                       UA_Byte *const paddingSize,
                                       UA_Byte *const extraPaddingSize) {

    if(securityPolicy == NULL || channelContext == NULL || endpointContext == NULL ||
       paddingSize == NULL || extraPaddingSize == NULL)
        return 0;

    UA_UInt16 plainTextBlockSize =
        (UA_UInt16)securityPolicy->channelContext.getRemoteAsymPlainTextBlockSize(securityPolicy,
                                                                                  channelContext);
    size_t signatureSize =
        securityPolicy->endpointContext.getLocalAsymSignatureSize(securityPolicy,
                                                                  endpointContext);
    UA_UInt16 padding =
        plainTextBlockSize - ((bytesToWrite + signatureSize + 1) % plainTextBlockSize);

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
static UA_StatusCode
hmacSha1(const UA_ByteString* const key,
         const UA_ByteString* const in,
         UA_ByteString* const out) {
    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
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

static UA_StatusCode
sym_verify_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                            const void *const context,
                            const UA_ByteString *const message,
                            const UA_ByteString *const signature) {
    if(securityPolicy == NULL || context == NULL ||
       message == NULL || signature == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;


    if(signature->length != securityPolicy->symmetricModule.signingModule.signatureSize) {
        UA_LOG_ERROR(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Signature size does not have the desired size defined by the security policy");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)context;

    UA_ByteString mac;
    UA_ByteString_allocBuffer(&mac, signature->length);

    hmacSha1(&data->remoteSymSigningKey, message, &mac);

    if(!UA_ByteString_equal(&mac, signature)) {
        UA_ByteString_deleteMembers(&mac);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_ByteString_deleteMembers(&mac);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sym_sign_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                          const void *const context,
                          const UA_ByteString *const message,
                          UA_ByteString *const signature) {
    UA_SP_basic128rsa15_ChannelContextData *const data =
        (UA_SP_basic128rsa15_ChannelContextData*)context;

    return hmacSha1(&data->localSymSigningKey, message, signature);
}

static UA_StatusCode
sym_encrypt_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                             const void *const channelContext,
                             UA_ByteString *const data) {

    if(securityPolicy == NULL || channelContext == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_SP_basic128rsa15_ChannelContextData *const contextData =
        (UA_SP_basic128rsa15_ChannelContextData*)channelContext;
    int mbedErr = 0;

    UA_assert(contextData->localSymIv.length == securityPolicy->symmetricModule.encryptingBlockSize);

    if(data->length % contextData->localSymEncryptingKey.length != 0) {
        UA_LOG_ERROR(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Length of data to encrypt is not a multiple of the encryptingKey length."
                     "Padding might not have been calculated appropriatley.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mbedtls_aes_context aesContext;

    mbedErr = mbedtls_aes_setkey_enc(&aesContext,
                                     contextData->localSymEncryptingKey.data,
                                     contextData->localSymEncryptingKey.length * 8); // *8 because we need bits here
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString encrypted;
    retval = UA_ByteString_allocBuffer(&encrypted, data->length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_ByteString ivCopy;
    retval = UA_ByteString_copy(&contextData->localSymIv, &ivCopy);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    mbedErr = mbedtls_aes_crypt_cbc(&aesContext,
                                    MBEDTLS_AES_ENCRYPT,
                                    data->length,
                                    ivCopy.data,
                                    data->data,
                                    encrypted.data);
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

static UA_StatusCode
sym_decrypt_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                             const void *const channelContext,
                             UA_ByteString *const data) {

    if(securityPolicy == NULL || channelContext == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_SP_basic128rsa15_ChannelContextData *const contextData =
        (UA_SP_basic128rsa15_ChannelContextData*)channelContext;
    int mbedErr = 0;

    UA_assert(contextData->remoteSymIv.length ==
              securityPolicy->symmetricModule.encryptingBlockSize);

    if(data->length % securityPolicy->symmetricModule.encryptingBlockSize != 0) {
        UA_LOG_ERROR(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "Length of data to decrypt is not a multiple of the encryptingBlock size.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mbedtls_aes_context aesContext;

    mbedErr = mbedtls_aes_setkey_dec(&aesContext,
                                     contextData->remoteSymEncryptingKey.data,
                                     contextData->remoteSymEncryptingKey.length * 8); // *8 because we need bits here
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString decrypted;
    retval = UA_ByteString_allocBuffer(&decrypted, data->length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_ByteString ivCopy;
    retval = UA_ByteString_copy(&contextData->remoteSymIv, &ivCopy);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    mbedErr = mbedtls_aes_crypt_cbc(&aesContext,
                                    MBEDTLS_AES_DECRYPT,
                                    data->length,
                                    ivCopy.data,
                                    data->data,
                                    decrypted.data);
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

static void
swapBuffers(UA_ByteString *const bufA, UA_ByteString *const bufB) {
    UA_ByteString tmp = *bufA;
    *bufA = *bufB;
    *bufB = tmp;
}

static UA_StatusCode
sym_generateKey_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                 const UA_ByteString *const secret,
                                 const UA_ByteString *const seed,
                                 UA_ByteString *const out) {
    if(securityPolicy == NULL || secret == NULL || seed == NULL || out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

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
        UA_Boolean bufferAllocated = UA_FALSE;
        // Not enough room in out buffer to write the hash.
        if(offset + hashLen > out->length) {
            outSegment.data = NULL;
            outSegment.length = 0;
            retval |= UA_ByteString_allocBuffer(&outSegment, hashLen);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_ByteString_deleteMembers(&A_and_seed);
                UA_ByteString_deleteMembers(&ANext_and_seed);
                return retval;
            }
            bufferAllocated = UA_TRUE;
        }

        retval |= hmacSha1(secret, &A_and_seed, &outSegment);
        retval |= hmacSha1(secret, &A, &ANext);

        if(retval != UA_STATUSCODE_GOOD) {
            if(bufferAllocated)
                UA_ByteString_deleteMembers(&outSegment);
            UA_ByteString_deleteMembers(&A_and_seed);
            UA_ByteString_deleteMembers(&ANext_and_seed);
            return retval;
        }
        else {
            if(bufferAllocated) {
                memcpy(out->data + offset, outSegment.data, out->length - offset);
                UA_ByteString_deleteMembers(&outSegment);
            }
        }

        swapBuffers(&ANext_and_seed, &A_and_seed);
        swapBuffers(&ANext, &A);
    }

    UA_ByteString_deleteMembers(&A_and_seed);
    UA_ByteString_deleteMembers(&ANext_and_seed);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sym_generateNonce_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
                                   const void *const endpointContext,
                                   UA_ByteString *const out) {

    if(securityPolicy == NULL || endpointContext == NULL || out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(mbedtls_ctr_drbg_random(&((UA_SP_basic128rsa15_EndpointContextData*)endpointContext)->drbgContext,
                               out->data,
                               out->length)
       != 0)
        return UA_STATUSCODE_BADUNEXPECTEDERROR;

    return UA_STATUSCODE_GOOD;
}

static UA_UInt16
sym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy *const securityPolicy,
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

static UA_StatusCode
deleteMembers_sp_basic128rsa15(UA_SecurityPolicy *const securityPolicy) {
    if(securityPolicy == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return securityPolicy->endpointContext.deleteMembers(securityPolicy,
                                                         securityPolicy->endpointContextData);
}


static UA_StatusCode init_sp_basic128rsa15(UA_SecurityPolicy *const securityPolicy, UA_Logger logger, void *const initData) {
    if(securityPolicy == NULL || logger == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityPolicy->logger = logger;

    // use defaults.
    if(initData == NULL) {
        UA_SecurityPolicy_Basic128Rsa15_initData defaultInitData = {
            NULL,
            0
        };

        return securityPolicy->endpointContext.init(securityPolicy,
                                                    &defaultInitData,
                                                    &securityPolicy->endpointContextData);
    }

    return securityPolicy->endpointContext.init(securityPolicy,
                                                initData,
                                                &securityPolicy->endpointContextData);
}

///////////////////////////////////
// End security policy functions //
///////////////////////////////////

UA_EXPORT UA_SecurityPolicy UA_SecurityPolicy_Basic128Rsa15 = {
    /* The policy uri that identifies the implemented algorithms */
    UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"), // .policyUri

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
            0, // .signatureSize // size_t signatureSize; in bytes .... Not applicable since dependant on rsa key length
            UA_STRING_STATIC("http://www.w3.org/2000/09/xmldsig#rsa-sha1\0") // .signatureAlgorithmUri
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
            20, // .signatureSize // size_t signatureSize; in bytes
            UA_STRING_STATIC("http://www.w3.org/2000/09/xmldsig#hmac-sha1\0") // .signatureAlgorithmUri
        },

    16, // .signingKeyLength
    16, // .encryptingKeyLength
    16 // .encryptingBlockSize
    },

    { // .endpointContext
        endpointContext_init_sp_basic128rsa15, // .init
        endpointContext_deleteMembers_sp_basic128rsa15, // .deleteMembers
        endpointContext_setServerPrivateKey_sp_basic128rsa15, // .setServerPrivateKey
        endpointContext_setCertificateTrustList_sp_basic128rsa15, // .setCertificateTrustList
        endpointContext_setCertificateRevocationList_sp_basic128rsa15, // .setCertificateRevocationList
        endpointContext_getLocalAsymSignatureSize_sp_basic128rsa15 // .getLocalAsymSignatureSize
    },

    { // .channelContext
        channelContext_init_sp_basic128rsa15,  // .init
        channelContext_deleteMembers_sp_basic128rsa15, // .deleteMembers

        channelContext_setLocalSymEncryptingKey_sp_basic128rsa15, // .setLocalSymEncryptingKey
        channelContext_setLocalSymSigningKey_sp_basic128rsa15, // .setLocalSymSigningKey
        channelContext_setLocalSymIv_sp_basic128rsa15, // .setLocalSymIv

        channelContext_setRemoteSymEncryptingKey_sp_basic128rsa15, // .setRemoteSymEncryptingKey
        channelContext_setRemoteSymSigningKey_sp_basic128rsa15, // .setRemoteSymSigningKey
        channelContext_setRemoteSymIv_sp_basic128rsa15, // .setRemoteSymIv

        channelContext_compareCertificate_sp_basic128rsa15, // .compareCertificate

        channelContext_getRemoteAsymSignatureSize_sp_basic128rsa15, // .getRemoteAsymSignatureSize
        channelContext_getRemoteAsymPlainTextBlockSize_sp_basic128rsa15, // .getRemoteAsymPlainTextBlockSize
        channelContext_getRemoteAsymEncryptionBufferLengthOverhead_sp_basic128rsa15 // .getRemoteAsymEncryptionBufferLengthOverhead
    },

    deleteMembers_sp_basic128rsa15, // .deleteMembers
    init_sp_basic128rsa15, // .init

    NULL, // .logger
    NULL // .endpointContextData
};

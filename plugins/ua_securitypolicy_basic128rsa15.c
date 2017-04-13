/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include "ua_securitypolicy_basic128rsa15.h"
#include "ua_types.h"
#include "ua_types_generated_handling.h"

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}

/////////////////////////////////
// Asymmetric module functions //
/////////////////////////////////

static UA_StatusCode asym_verify_sp_basic128rsa15(const UA_ByteString* const message,
                                         const UA_ByteString* const signature,
                                         const void* const context) {
    return UA_STATUSCODE_GOOD;
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
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode asym_makeThumbprint_sp_basic128rsa15(const UA_ByteString* const certificate,
                                                 UA_ByteString* const thumbprint) {
    if(certificate == NULL || thumbprint == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode asym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy* const securityPolicy,
                                                   const size_t bytesToWrite,
                                                   UA_Byte* const paddingSize,
                                                   UA_Byte* const extraPaddingSize) {
    *paddingSize = 0;
    *extraPaddingSize = 0;
    return UA_STATUSCODE_GOOD;
}

/////////////////////////////////////
// End asymmetric module functions //
/////////////////////////////////////

////////////////////////////////
// Symmetric module functions //
////////////////////////////////

static UA_StatusCode sym_verify_sp_basic128rsa15(const UA_ByteString* const message,
                                        const UA_ByteString* const signature,
                                        const void* const context) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_sign_sp_basic128rsa15(const UA_ByteString* const message,
                                      const void* const context,
                                      UA_ByteString* const signature) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_encrypt_sp_basic128rsa15(const UA_Channel_SecurityContext* const securityContext,
                                         UA_ByteString* const data) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_decrypt_sp_basic128rsa15(const UA_Channel_SecurityContext* const securityContext,
                                         UA_ByteString* const data) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_generateKey_sp_basic128rsa15(const UA_ByteString* const secret,
                                             const UA_ByteString* const seed,
                                             const size_t length,
                                             UA_ByteString* const out) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_generateNonce_sp_basic128rsa15(const UA_SecurityPolicy* const securityPolicy,
                                               UA_ByteString* const out) {
    out->length = securityPolicy->symmetricModule.encryptingKeyLength;
    out->data[0] = 'a';

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode sym_calculatePadding_sp_basic128rsa15(const UA_SecurityPolicy* const securityPolicy,
                                                  const size_t bytesToWrite,
                                                  UA_Byte* const paddingSize,
                                                  UA_Byte* const extraPaddingSize) {
    *paddingSize = 0;
    *extraPaddingSize = 0;
    return UA_STATUSCODE_GOOD;
}

////////////////////////////////////
// End symmetric module functions //
////////////////////////////////////

///////////////////////////////
// Security policy functions //
///////////////////////////////
static UA_StatusCode verifyCertificate_sp_basic128rsa15(const UA_ByteString* const certificate,
                                               const UA_Policy_SecurityContext* const context) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode deleteMembers_sp_basic128rsa15(UA_SecurityPolicy* const securityPolicy) {
    if(securityPolicy == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return securityPolicy->context.deleteMembers(&securityPolicy->context);
}


static UA_StatusCode init_sp_basic128rsa15(UA_SecurityPolicy* const securityPolicy, UA_Logger logger) {
    if(securityPolicy == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityPolicy->logger = logger;

    return securityPolicy->context.init(&securityPolicy->context, logger);
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

/////////////////////////////
// PolicyContext functions //
/////////////////////////////

typedef struct {
    int callCounter;
} UA_SP_basic128rsa15_PolicyContextData;

static UA_StatusCode policyContext_init_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                UA_Logger logger) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityContext->data = (UA_SP_basic128rsa15_PolicyContextData*)UA_malloc(sizeof(UA_SP_basic128rsa15_PolicyContextData));

    if(securityContext->data == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    // Initialize the PolicyContext data to sensible values
    UA_SP_basic128rsa15_PolicyContextData* data = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    data->callCounter = 0;

    securityContext->logger = logger;

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Initialized PolicyContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_deleteMembers_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // delete all allocated members in the data block
    UA_SP_basic128rsa15_PolicyContextData* data = (UA_SP_basic128rsa15_PolicyContextData*)securityContext->data;

    data->callCounter = 0;

    UA_free(securityContext->data);

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Deleted members of PolicyContext for sp_basic128rsa15");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setServerPrivateKey_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                               const UA_ByteString* const privateKey) {
    if(securityContext == NULL || privateKey == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setCertificateTrustList_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                                   const UA_ByteString* const trustList) {
    if(securityContext == NULL || trustList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode policyContext_setCertificateRevocationList_sp_basic128rsa15(UA_Policy_SecurityContext* const securityContext,
                                                                        const UA_ByteString* const revocationList) {
    if(securityContext == NULL || revocationList == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

/////////////////////////////////
// End PolicyContext functions //
/////////////////////////////////

//////////////////////////////
// ChannelContext functions //
//////////////////////////////

// this is not really needed in security policy none because no context is required
// it is there to serve as a small example for policies that need context per channel
typedef struct {
    int callCounter;
} UA_SP_basic128rsa15_ChannelContextData;

static UA_StatusCode channelContext_init_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext, UA_Logger logger) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityContext->data = (UA_SP_basic128rsa15_ChannelContextData*)UA_malloc(sizeof(UA_SP_basic128rsa15_ChannelContextData));
    if(securityContext->data == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    // Initialize the channelcontext data here to sensible values
    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter = 0;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_deleteMembers_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext) {
    if(securityContext == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Delete the member variables that eventually were allocated in the init method
    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Call counter was %i before deletion.", data->callCounter);

    data->callCounter = 0;

    UA_free(securityContext->data);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setLocalEncryptingKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                  const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        fprintf(stderr, "Error while calling channelContext_setLocalEncryptingKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setLocalSigningKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                               const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        fprintf(stderr, "Error while calling channelContext_setLocalSigningKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode channelContext_setLocalIv_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                       const UA_ByteString* const iv) {
    if(securityContext == NULL || iv == NULL) {
        fprintf(stderr, "Error while calling channelContext_setLocalIv_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setRemoteEncryptingKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                   const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        fprintf(stderr, "Error while calling channelContext_setRemoteEncryptingKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setRemoteSigningKey_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                const UA_ByteString* const key) {
    if(securityContext == NULL || key == NULL) {
        fprintf(stderr, "Error while calling channelContext_setRemoteSigningKey_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_setRemoteIv_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                        const UA_ByteString* const iv) {
    if(securityContext == NULL || iv == NULL) {
        fprintf(stderr, "Error while calling channelContext_setRemoteIv_sp_basic128rsa15. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_basic128rsa15_ChannelContextData* const data = (UA_SP_basic128rsa15_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode channelContext_parseClientCertificate_sp_basic128rsa15(UA_Channel_SecurityContext* const securityContext,
                                                                   const UA_ByteString* const clientCertificate) {
    if(securityContext == NULL || clientCertificate == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

//////////////////////////////////
// End ChannelContext functions //
//////////////////////////////////

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

        20, // .thumbprintLength

            /* Asymmetric signing module */
        {
            asym_verify_sp_basic128rsa15, // .verify
            asym_sign_sp_basic128rsa15, // .sign
            0 // .signatureSize // size_t signatureSize; in bytes
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
            0 // .signatureSize // size_t signatureSize; in bytes
        },

    0, // .signingKeyLength
    1, // .encryptingKeyLength
    0 // .encryptingBlockSize
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

        channelContext_parseClientCertificate_sp_basic128rsa15, // .parseClientCertificate

        NULL, // .logger
        NULL // .data
    },

    makeChannelContext_sp_basic128rsa15, // .makeChannelContext
    NULL // .logger
};

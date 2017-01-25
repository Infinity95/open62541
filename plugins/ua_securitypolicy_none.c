/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
* See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include "ua_securitypolicy_none.h"
#include <stdio.h>

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}

/////////////////////////////////
// Asymmetric module functions //
/////////////////////////////////

UA_StatusCode asym_verify_sp_none(const UA_ByteString* const message,
                                  const void* const context)
{
    return 0;
}

UA_StatusCode asym_sign_sp_none(const UA_ByteString* const message,
                                const void* const context,
                                UA_ByteString* const signature)
{
    return 0;
}

UA_StatusCode asym_encrypt_sp_none(const UA_ByteString* const plainText,
                                   const UA_Policy_SecurityContext* const securityContext,
                                   UA_ByteString* const cipher)
{
    return 0;
}

UA_StatusCode asym_decrypt_sp_none(const UA_ByteString* const cipher,
                                   const UA_Policy_SecurityContext* const securityContext,
                                   UA_ByteString* const decrypted)
{
    return 0;
}

/////////////////////////////////////
// End asymmetric module functions //
/////////////////////////////////////

////////////////////////////////
// Symmetric module functions //
////////////////////////////////

UA_StatusCode sym_verify_sp_none(const UA_ByteString* const message,
                                 const void* const context)
{
    return 0;
}

UA_StatusCode sym_sign_sp_none(const UA_ByteString* const message,
                               const void* const context,
                               UA_ByteString* const signature)
{
    return 0;
}

UA_StatusCode sym_encrypt_sp_none(const UA_ByteString* const plainText,
                                  const UA_Channel_SecurityContext* const securityContext,
                                  UA_ByteString* const cipher)
{
    return 0;
}

UA_StatusCode sym_decrypt_sp_none(const UA_ByteString* const cipher,
                                  const UA_Channel_SecurityContext* const securityContext,
                                  UA_ByteString* const decrypted)
{
    return 0;
}

UA_StatusCode generateKey_sp_none(const UA_ByteString* const secret,
                                  const UA_ByteString* const seed,
                                  const UA_Int32 length,
                                  const UA_Int32 offset,
                                  UA_ByteString* const output)
{
    return 0;
}

////////////////////////////////////
// End symmetric module functions //
////////////////////////////////////

///////////////////////////////
// Security policy functions //
///////////////////////////////
UA_StatusCode verifyCertificate_sp_none(const UA_ByteString* const certificate,
                                        const UA_Policy_SecurityContext* const context)
{
    return 0;
}

UA_StatusCode deleteMembers_sp_none(UA_SecurityPolicy* const securityPolicy)
{
    if (securityPolicy == NULL)
    {
        goto error;
    }

    return UA_STATUSCODE_GOOD;

error:
    return UA_STATUSCODE_BADINTERNALERROR;
}


UA_StatusCode init_sp_none(UA_SecurityPolicy* const securityPolicy, UA_Logger logger)
{
    if (securityPolicy == NULL)
    {
        goto error;
    }

    securityPolicy->logger = logger;

    return UA_STATUSCODE_GOOD;

error:
    return UA_STATUSCODE_BADINTERNALERROR;
}

UA_Channel_SecurityContext makeChannelContext_sp_none(UA_SecurityPolicy* const securityPolicy)
{
    return securityPolicy->channelContextPrototype;
}
///////////////////////////////////
// End security policy functions //
///////////////////////////////////

//////////////////////////////
// ChannelContext functions //
//////////////////////////////

// this is not really needed in security policy none because no context is required
// it is there to serve as a small example for policies that need context per channel
typedef struct
{
    int callCounter;
} UA_SP_NONE_ChannelContextData;

UA_StatusCode channelContext_init_sp_none(UA_Channel_SecurityContext* const securityContext, UA_Logger logger)
{
    if (securityContext == NULL)
    {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    securityContext->data = UA_malloc(sizeof(UA_SP_NONE_ChannelContextData));
    if (securityContext->data == NULL)
    {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    // Initialize the channelcontext data here to sensible values
    UA_SP_NONE_ChannelContextData* const data = (UA_SP_NONE_ChannelContextData*)securityContext->data;

    data->callCounter = 0;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode channelContext_deleteMembers_sp_none(UA_Channel_SecurityContext* const securityContext)
{
    if (securityContext == NULL)
    {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    // Delete the member variables that eventually were allocated in the init method
    UA_SP_NONE_ChannelContextData* const data = (UA_SP_NONE_ChannelContextData*)securityContext->data;

    UA_LOG_DEBUG(securityContext->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Call counter was %i before deletion.", data->callCounter);

    data->callCounter = 0;

    UA_free(securityContext->data);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode channelContext_setServerKey_sp_none(UA_Channel_SecurityContext* const securityContext,
                                                  const UA_ByteString* const serverKey)
{
    if (securityContext == NULL || serverKey == NULL)
    {
        fprintf(stderr, "Error while calling channelContext_setServerKey_sp_none. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_NONE_ChannelContextData* const data = (UA_SP_NONE_ChannelContextData*)securityContext->data;

    data->callCounter++;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode channelContext_setClientKey_sp_none(UA_Channel_SecurityContext* const securityContext,
                                                  const UA_ByteString* const clientKey)
{
    if (securityContext == NULL || clientKey == NULL)
    {
        fprintf(stderr, "Error while calling channelContext_setClientKey_sp_none. Null pointer passed.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SP_NONE_ChannelContextData* const data = (UA_SP_NONE_ChannelContextData*)securityContext->data;

    data->callCounter++;
    
    return UA_STATUSCODE_GOOD;
}

//////////////////////////////////
// End ChannelContext functions //
//////////////////////////////////

UA_EXPORT UA_SecurityPolicy UA_SecurityPolicy_None = {
    /* The policy uri that identifies the implemented algorithms */
    .policyUri = UA_STRING_STATIC("https://opcfoundation.org/UA/SecurityPolicy/#None"),

    .verifyCertificate = verifyCertificate_sp_none,

    /* Asymmetric module */
    .asymmetricModule = {
        .encrypt = asym_encrypt_sp_none,
        
        .decrypt = asym_decrypt_sp_none,

        /* Asymmetric signing module */
        {
            .verify = asym_verify_sp_none,

            .sign = asym_sign_sp_none,

            .signatureSize = 0 //size_t signatureSize; in bytes
        }
    },

    /* Symmetric module */
    .symmetricModule = {
        .encrypt = sym_encrypt_sp_none,

        .decrypt = sym_decrypt_sp_none,

        .generateKey = generateKey_sp_none,

        /* Symmetric signing module */
        .signingModule = {
            .verify = sym_verify_sp_none,

            .sign = sym_sign_sp_none,

            .signatureSize = 0 //size_t signatureSize; in bytes
        },

        .signingKeyLength = 0,
        .encryptingKeyLength = 0,
        .encryptingBlockSize = 0
    },
    
    .context = {
        NULL
    },

    .deleteMembers = deleteMembers_sp_none,
    .init = init_sp_none,

    /* Channel context prototype */
    .channelContextPrototype = {
        .init = channelContext_init_sp_none,

        .deleteMembers = channelContext_deleteMembers_sp_none,
        
        .setServerKey = channelContext_setServerKey_sp_none,

        .setClientKey = channelContext_setClientKey_sp_none,

        .data = NULL // data
    },

    .makeChannelContext = makeChannelContext_sp_none
};
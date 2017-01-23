/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
* See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include "ua_securitypolicy_none.h"

#define UA_STRING_STATIC(s) {sizeof(s)-1, (UA_Byte*)s}
#define UA_STRING_STATIC_NULL {0, NULL}

////////////////////////////////
// Symmetric module functions //
////////////////////////////////

UA_StatusCode asym_encrypt_sp_none(const UA_ByteString* const plainText,
                                   const UA_Channel_SecurityContext* const securityContext,
                                   UA_ByteString* const cipher)
{
    return 0;
}

UA_StatusCode asym_decrypt_sp_none(const UA_ByteString* const cipher,
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
    return 0;
}


UA_StatusCode init_sp_none(UA_SecurityPolicy* const securityPolicy, size_t argc, UA_SecurityPolicyArgs args[])
{
    return 0;
}
///////////////////////////////////
// End security policy functions //
///////////////////////////////////

UA_EXPORT const UA_SecurityPolicy UA_SecurityPolicy_None = {
    /* The policy uri that identifies the implemented algorithms */
    UA_STRING_STATIC("https://opcfoundation.org/UA/SecurityPolicy/#None"),

    verifyCertificate_sp_none,

    {
    
    },//const UA_SecurityPolicyAsymmetricModule asymmetricModule
    {
        asym_encrypt_sp_none,

        asym_decrypt_sp_none,

        generateKey_sp_none,

        {
        
        },//const UA_SecurityPolicySigningModule signingModule;

        0, //const size_t signingKeyLength;
        0, //const size_t encryptingKeyLength;
        0 //const size_t encryptingBlockSize;
    },//const UA_SecurityPolicySymmetricModule symmetricModule
    
    // const UA_Policy_SecurityContext* context
    NULL,

    deleteMembers_sp_none,
    init_sp_none
};
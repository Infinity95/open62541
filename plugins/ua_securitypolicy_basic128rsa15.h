/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UA_SECURITYPOLICY_BASIC128RSA15_H_
#define UA_SECURITYPOLICY_BASIC128RSA15_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_securitypolicy.h"

typedef int(*UA_EntropySourceFunc_sp_basic128rsa15)(void *data, unsigned char *output, size_t len, size_t *olen);

/** TODO: document
 * For more information see mbedtls documentation on mbedtls entropy
 */
typedef struct {
    UA_EntropySourceFunc_sp_basic128rsa15 entropyFunc;
    void *entropySource;
    /* Minimum required from source before entropy is released ( with mbedtls_entropy_func() ) (in bytes)  */
    size_t threshold;
    int strong;
} UA_EntropySource_sp_basic128rsa15;

typedef struct {
    /** The number of entropy source */
    size_t count;
    /** The entropy source array */
    UA_EntropySource_sp_basic128rsa15 *sources;
} UA_EntropySources_sp_basic128rsa15;

typedef struct {
    const unsigned char *ctrDrbg_personalizationData;
    size_t ctrDrbg_personalizationDataLen;

    UA_EntropySources_sp_basic128rsa15 entropySources;
} UA_SecurityPolicy_Basic128Rsa15_initData;

extern UA_EXPORT UA_SecurityPolicy UA_SecurityPolicy_Basic128Rsa15;

#ifdef __cplusplus
}
#endif

#endif // UA_SECURITYPOLICY_BASIC128RSA15_H_

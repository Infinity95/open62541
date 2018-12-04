/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H
#define OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H

#include "ua_plugin_socket.h"

typedef struct UA_NetworkManager UA_NetworkManager;

struct UA_NetworkManager {
    UA_StatusCode (*registerSocket)(UA_NetworkManager *networkManager, UA_Socket *socket);

    UA_StatusCode (*unregisterSocket)(UA_NetworkManager *networkManager, UA_Socket *socket);

    UA_StatusCode (*process)(UA_NetworkManager *networkManager, UA_UInt16 timeout);

    UA_StatusCode (*deleteMembers)(UA_NetworkManager *networkManager);

    void *internalData;
};

#endif //OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H

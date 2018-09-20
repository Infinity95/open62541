/**
 * EXPERIMENTAL Network Managers
 */

#ifndef OPEN62541_UA_NETWORK_MANAGERS_H
#define OPEN62541_UA_NETWORK_MANAGERS_H

#include "ua_plugin_network_manager.h"

UA_StatusCode
UA_SelectBasedNetworkManager(UA_NetworkManager *networkManager);

#endif //OPEN62541_UA_NETWORK_MANAGERS_H

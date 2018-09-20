/**
 * EXPERIMENTAL Network Manager
 */

#ifndef OPEN62541_UA_NETWORK_MANAGER_H
#define OPEN62541_UA_NETWORK_MANAGER_H

#include "ua_types.h"
#include "ua_plugin_log.h"
#include "ua_plugin_socket.h"

/*
 * The Sequence could be as follows:
 *
 *
 *        The server has a network manager
 *    [Server]              [Network Manager]
 *        |                          |
 *        |        init              |
 *        |------------------------->|
 *        |                          |
 *        |     create_listener      |
 *        |------------------------->|
 *        |                          |
 *        |       inc_conn_cb        |
 *        ||<------------------------|
 *        ||                         |         [SecureChannel]
 *        ||                         |                |
 *        ||------------------------------------------|
 *        |                          |                |
 *        |                          |                |
 *        |                          |                |
 *        |                          |                |
 *        |                          |                |
 *        |                          |                |
 */

typedef struct {
    void *internalData;
} UA_NetworkManager;


UA_StatusCode
UA_NetworkManager_init(UA_NetworkManager *networkManager, UA_Logger logger);

UA_StatusCode
UA_NetworkManager_deleteMembers(UA_NetworkManager *networkManager);

UA_StatusCode
UA_NetworkManager_addSocket(UA_NetworkManager *networkManager,
                            UA_Socket socket);

UA_StatusCode
UA_NetworkManager_process(UA_NetworkManager *networkManager,
                          UA_Int32 timeout);

#endif //OPEN62541_UA_NETWORK_MANAGER_H

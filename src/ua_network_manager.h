/**
 * EXPERIMENTAL Network Manager
 */

#ifndef OPEN62541_UA_NETWORK_MANAGER_H
#define OPEN62541_UA_NETWORK_MANAGER_H

#include <ua_types.h>
#include <ua_plugin_network.h>

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


#define UA_LISTENER_SOCKET_COUNT FD_SETSIZE
#define UA_CONNECTION_SOCKET_COUNT FD_SETSIZE

/*
 * This callback is called after a new connection was created by the network manager
 * in response to a new tcp connection on a listener socket.
 */
typedef UA_StatusCode (*UA_Socket_activityCallback)(void);

typedef int (*UA_Socket_getFileDescriptor)(void);

typedef UA_StatusCode (*UA_Socket_timeoutCheckCallback)(void);

typedef struct {
    UA_Socket_activityCallback activityCallback;
    UA_Socket_timeoutCheckCallback timeoutCheckCallback;
    UA_Socket_getFileDescriptor getFileDescriptor;
} UA_Socket;

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

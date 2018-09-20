#ifndef OPEN62541_UA_PLUGIN_SOCKET_H
#define OPEN62541_UA_PLUGIN_SOCKET_H

#include "ua_types.h"

/*
 * This callback is called after activity was detected by the network manager.
 * The socket can process any outstanding data and put it into a processing queue.
 */
typedef UA_StatusCode (*UA_Socket_activityCallback)(void);

typedef int (*UA_Socket_getFileDescriptor)(void);

typedef UA_StatusCode (*UA_Socket_timeoutCheckCallback)(UA_DateTime now);

typedef struct {
    UA_Socket_activityCallback activityCallback;
    UA_Socket_timeoutCheckCallback timeoutCheckCallback;
    UA_Socket_getFileDescriptor getFileDescriptor;
} UA_Socket;

#endif //OPEN62541_UA_PLUGIN_SOCKET_H

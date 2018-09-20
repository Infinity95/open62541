#ifndef OPEN62541_UA_PLUGIN_SOCKET_H
#define OPEN62541_UA_PLUGIN_SOCKET_H

#include "ua_types.h"

struct UA_Socket;
typedef struct UA_Socket UA_Socket;

struct UA_Socket {
    UA_StatusCode (*init)(UA_Socket *socket);

    UA_StatusCode (*deleteMembers)(UA_Socket *socket);

    /**
     * Returns a file descriptor if the socket implementation supports file descriptors.
     * Otherwise this function pointer will be NULL.
     */
    int (*getFileDescriptor)(void);

    UA_StatusCode (*setPacketProcessingCallback)(UA_Socket *socket);

    void *internalData;
};

/**
 * This scruct contains internal function pointers that are only used by the socket and network manager.
 * It defines the api between network manager and socket.
 */
typedef struct {
    UA_StatusCode (*activityCallback)(void);

    UA_StatusCode (*timeoutCheckCallback)(UA_DateTime now);

    UA_StatusCode (*completePacketCallback)(UA_ByteString *buffer, void *userData);
} UA_Socket_internalData;

#endif //OPEN62541_UA_PLUGIN_SOCKET_H

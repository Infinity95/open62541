#ifndef OPEN62541_UA_PLUGIN_SOCKET_H
#define OPEN62541_UA_PLUGIN_SOCKET_H

#include "ua_types.h"
#include "ua_plugin_log.h"

struct UA_Socket;
typedef struct UA_Socket UA_Socket;

typedef UA_StatusCode (*UA_Socket_processCompletePacketCallback)(UA_ByteString *buffer, void *userData);

struct UA_Socket {
    UA_StatusCode (*deleteMembers)(UA_Socket *socket);

    /**
     * Returns a file descriptor if the socket implementation supports file descriptors.
     * Otherwise this function pointer will be NULL.
     */
    int (*getFileDescriptor)(void);

    /**
     * Sets the callback function that is called on complete packets.
     * The buffer that is passed to the callback will be deleted after the call,
     * so any data that needs to be kept beyond the call duration needs to be copied.
     *
     * @param socket
     * @param userData
     * @return
     */
    UA_StatusCode (*setPacketProcessingCallback)(UA_Socket *socket, UA_Socket_processCompletePacketCallback,
                                                 void *userData);

    void *internalData;
};

#endif //OPEN62541_UA_PLUGIN_SOCKET_H

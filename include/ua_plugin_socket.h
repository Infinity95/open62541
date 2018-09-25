#ifndef OPEN62541_UA_PLUGIN_SOCKET_H
#define OPEN62541_UA_PLUGIN_SOCKET_H

#include "ua_types.h"
#include "ua_plugin_log.h"
#include "ua_plugin_network.h"

struct UA_Socket;
typedef struct UA_Socket UA_Socket;

typedef UA_StatusCode (*UA_Socket_processCompletePacketCallback)(UA_ByteString *buffer, void *userData);

/**
 * Functions that implement this signature will be called
 * after a new socket was created, in order to manage them.
 * The server for example can be passed as userData and
 * the callback can then add the new socket to a list in the server.
 */
typedef UA_StatusCode  (*UA_Socket_creationCallback)(UA_Socket *socket, void *userData);

/**
 * Functions that implement this signature need to call
 * the creationCallback with the newly created socket and the userData
 * as parameters. The creationCallback is then responsible for
 * further managing the newly created socket.
 */
typedef UA_StatusCode (*UA_SocketCreationFunc)(void *configData,
                                               UA_Socket_creationCallback creationCallback,
                                               void *userData);

/**
 * Each socket may implement different initialization/creation functions.
 * This struct abstracts away from implementation specific behavior.
 * The configuration data is saved in the configData void pointer and
 * will be passed to the socketCreationFunc in the calling code.
 * This makes it possible to have implementation independent code
 * in e.g. the server. The different interfaces only need to be considered
 * in the configuration.
 */
typedef struct {
    UA_SocketCreationFunc socketCreationFunc;
    void *configData;
} UA_SocketCreationData;

/**
 * This is a utility wrapper that contains an additional connectionConfig
 * which is needed for listener sockets. // TODO: Is this sensible? Client side?
 */
typedef struct UA_ListenerSocketConfig {
    UA_ConnectionConfig connectionConfig;
    UA_SocketCreationData socketCreationData;
} UA_ListenerSocketConfig;

struct UA_Socket {
    UA_StatusCode (*deleteMembers)(UA_Socket *socket);

    /**
     * Returns a file descriptor if the socket implementation supports file descriptors.
     * Otherwise this function pointer will be NULL.
     */
    int (*getFileDescriptor)(UA_Socket *socket);

    /**
     * Sets the callback function that is called on complete packets.
     * The buffer that is passed to the callback will be deleted after the call,
     * so any data that needs to be kept beyond the call duration needs to be copied.
     *
     * \param socket
     * \param userData
     * \return
     */
    UA_StatusCode (*setPacketProcessingCallback)(UA_Socket *socket, UA_Socket_processCompletePacketCallback,
                                                 void *userData);

    /**
     * Retrieves the discovery url of the socket if applicable.
     * Client sockets for example will return a NULL string, since
     * they don't have a discovery url.
     *
     * \param socket
     * \param discoverUrlBuffer
     * \return
     */
    UA_StatusCode (*getDiscoveryUrl)(UA_Socket *socket, UA_String *discoveryUrlBuffer);

    void *internalData;
};

#endif //OPEN62541_UA_PLUGIN_SOCKET_H

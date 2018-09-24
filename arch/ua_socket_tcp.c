#include "ua_plugin_socket.h"
#include "ua_socket_tcp.h"
#include "ua_plugin_network_manager.h"

static UA_StatusCode
UA_Socket_TCP_activityCallback(UA_Socket *socket) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Socket_TCPListener_activityCallback(UA_Socket *socket) {
    if(socket == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    struct sockaddr_storage remote;
    socklen_t remote_size = sizeof(remote);
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)socket->internalData;
    int newsockfd = UA_accept(socket->getFileDescriptor(), (struct sockaddr *)&remote, &remote_size);
    if(newsockfd == -1) {
        UA_LOG_ERROR(internalData->logger, UA_LOGCATEGORY_NETWORK,
                     "Invalid file descriptor returned during accept call");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOG_TRACE(internalData->logger, UA_LOGCATEGORY_NETWORK,
                 "Connection %i | New TCP connection on server socket %i",
                 newsockfd, socket->getFileDescriptor());

    return internalData->completePacketCallback(socket, NULL);

    // ServerNetworkLayerTCP_add(nl, layer, (UA_Int32)newsockfd, &remote);
}

static UA_StatusCode
UA_Socket_TCP_deleteMembers(UA_Socket *socket) {
    UA_free(socket->internalData);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCP(UA_Socket *socket, UA_Logger logger) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)UA_malloc(sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    internalData->activityCallback = UA_Socket_TCP_activityCallback;
    internalData->logger = logger;

    socket->internalData = internalData;

    socket->deleteMembers = UA_Socket_TCP_deleteMembers;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCPListener(UA_Socket *socket, UA_Logger logger) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)UA_malloc(sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    internalData->activityCallback = UA_Socket_TCPListener_activityCallback;
    internalData->logger = logger;

    socket->internalData = internalData;

    socket->deleteMembers = UA_Socket_TCP_deleteMembers;
    return UA_STATUSCODE_GOOD;
}

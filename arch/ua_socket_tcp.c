#include "ua_plugin_socket.h"
#include "ua_socket_tcp.h"
#include "ua_plugin_network_manager.h"

typedef struct {
    int fd;
    UA_String customHostname;
    UA_UInt16 port;
}
    TcpSocketInternalData;

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
                 newsockfd, socket->getFileDescriptor(socket));

    return internalData->completePacketCallback(NULL, NULL);

    // ServerNetworkLayerTCP_add(nl, layer, (UA_Int32)newsockfd, &remote);
}

static int
UA_Socket_TCP_getFileDescriptor(UA_Socket *socket) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)socket->internalData;
    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)internalData->implementationSpecificData;

    return implementationSpecificData->fd;
}

static UA_StatusCode
UA_Socket_TCP_getDiscoverUrl(UA_Socket *socket, UA_String *discoveryUrlBuffer) {
    *discoveryUrlBuffer = UA_BYTESTRING_NULL;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Socket_TCPListener_getDiscoveryUrl(UA_Socket *socket, UA_String *discoveryUrlBuffer) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)socket->internalData;
    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)internalData->implementationSpecificData;

    UA_String du = UA_STRING_NULL;
    char duBuffer[256];
    char hostnameBuffer[256];
    if(implementationSpecificData->customHostname.length) {
        du.length = (size_t)UA_snprintf(duBuffer, 255, "opc.tcp://%.*s:%d/",
                                        (int)implementationSpecificData->customHostname.length,
                                        implementationSpecificData->customHostname.data,
                                        implementationSpecificData->port);
        du.data = (UA_Byte *)duBuffer;
    } else {
        if(UA_gethostname(hostnameBuffer, 255) == 0) {
            du.length = (size_t)UA_snprintf(duBuffer, 255, "opc.tcp://%s:%d/",
                                            hostnameBuffer, implementationSpecificData->port);
            du.data = (UA_Byte *)duBuffer;
        } else {
            UA_LOG_ERROR(internalData->logger, UA_LOGCATEGORY_NETWORK, "Could not get the hostname");
        }
    }

    return UA_String_copy(&du, discoveryUrlBuffer);
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

    socket->getFileDescriptor = UA_Socket_TCP_getFileDescriptor;
    socket->getDiscoveryUrl = UA_Socket_TCP_getDiscoverUrl;
    socket->deleteMembers = UA_Socket_TCP_deleteMembers;

    internalData->activityCallback = UA_Socket_TCP_activityCallback;
    internalData->logger = logger;

    socket->internalData = internalData;

    socket->deleteMembers = UA_Socket_TCP_deleteMembers;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCPListener(UA_Socket *socket, UA_UInt16 port, UA_String *customHostname, struct addrinfo *addrinfo,
                      UA_Logger logger) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)UA_malloc(sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)UA_malloc(sizeof(TcpSocketInternalData));

    implementationSpecificData->port = port;
    UA_ByteString_copy(customHostname, &implementationSpecificData->customHostname);

    socket->getFileDescriptor = UA_Socket_TCP_getFileDescriptor;
    socket->getDiscoveryUrl = UA_Socket_TCPListener_getDiscoveryUrl;
    socket->deleteMembers = UA_Socket_TCP_deleteMembers;

    internalData->activityCallback = UA_Socket_TCPListener_activityCallback;
    internalData->logger = logger;

    internalData->implementationSpecificData = implementationSpecificData;
    socket->internalData = internalData;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCPListener_create(UA_Socket_TCP_ConfigData *configData, UA_Socket_creationCallback creationCallback,
                             void *userData) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    struct addrinfo *ai = configData->addrinfo;
    UA_Boolean internallyAllocated = UA_FALSE;

    if(ai == NULL) {
        char portno[6];
        UA_snprintf(portno, 6, "%d", configData->port);
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;
        if(UA_getaddrinfo(NULL, portno, &hints, &res) != 0)
            return UA_STATUSCODE_BADINTERNALERROR;

        ai = res;

        internallyAllocated = UA_TRUE;
    }

    UA_Socket *socket = NULL;
    for(; ai != NULL; ai = ai->ai_next) {
        socket = (UA_Socket *)UA_malloc(sizeof(UA_Socket));
        retval = UA_Socket_TCPListener(socket, configData->port, configData->customHostname, ai, configData->logger);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
        retval = creationCallback(socket, userData);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

cleanup:
    if(socket != NULL)
        UA_free(socket);

    if(internallyAllocated)
        UA_freeaddrinfo(ai);

    return retval;
}

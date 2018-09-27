#include "ua_plugin_socket.h"
#include "ua_socket_tcp.h"
#include "ua_plugin_network_manager.h"

#define MAXBACKLOG 100

typedef struct {
    int fd;
    UA_String customHostname;
    UA_UInt16 port;
} TcpSocketInternalData;

static UA_StatusCode
UA_Socket_TCP_activityCallback(UA_Socket *socket) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Socket_TCPListener_activityCallback(UA_Socket *socket) {
    if(socket == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)socket->internalData;

    if(internalData->completePacketCallback.callback == NULL) {
        UA_LOG_ERROR(internalData->logger, UA_LOGCATEGORY_NETWORK, "No completePacket callback set for socket");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return internalData->completePacketCallback.callback(socket, NULL, internalData->completePacketCallback.userData);
}

static UA_StatusCode
UA_Socket_TCPListener_timeoutCheckCallback(UA_Socket *socket, UA_DateTime timeout) {
    return UA_STATUSCODE_GOOD;
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

static UA_StatusCode
UA_Socket_TCP_setPacketProcessingCallback(UA_Socket *socket,
                                          UA_Socket_processCompletePacketCallback processCompletePacketCallback) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)socket->internalData;

    internalData->completePacketCallback = processCompletePacketCallback;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Socket_TCP_setupInternal(UA_Socket *socket, UA_Logger logger) {
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)UA_calloc(1, sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)UA_calloc(1, sizeof(TcpSocketInternalData));
    if(implementationSpecificData == NULL) {
        UA_free(internalData);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    internalData->implementationSpecificData = implementationSpecificData;
    internalData->activityCallback = UA_Socket_TCP_activityCallback;
    internalData->logger = logger;

    socket->internalData = internalData;
    socket->getFileDescriptor = NULL;
    socket->getDiscoveryUrl = UA_Socket_TCP_getDiscoverUrl;
    socket->deleteMembers = UA_Socket_TCP_deleteMembers;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCP(UA_Socket *socket, UA_Logger logger) {
    return UA_Socket_TCP_setupInternal(socket, logger);
}

static UA_StatusCode
UA_Socket_TCPListener_setup(UA_Socket_internalData *internalData,
                            TcpSocketInternalData *implementationSpecificData,
                            struct addrinfo *addrinfo) {
    implementationSpecificData->fd = UA_socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    int fd = implementationSpecificData->fd;
    if(fd == UA_INVALID_SOCKET) {
        UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                       "Error opening the server socket");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Some Linux distributions have net.ipv6.bindv6only not activated. So
     * sockets can double-bind to IPv4 and IPv6. This leads to problems. Use
     * AF_INET6 sockets only for IPv6. */

    int optval = 1;
#if UA_IPV6
    if(addrinfo->ai_family == AF_INET6 &&
       UA_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                     (const char *)&optval, sizeof(optval)) == -1) {
        UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set an IPv6 socket to IPv6 only");
        UA_close(fd);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
#endif
    if(UA_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&optval, sizeof(optval)) == -1) {
        UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not make the socket reusable");
        UA_close(fd);
        return UA_STATUSCODE_BADINTERNALERROR;
    }


    if(UA_socket_set_nonblocking(fd) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set the server socket to nonblocking");
        UA_close(fd);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Bind socket to address */
    if(UA_bind(fd, addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                           "Error binding a server socket: %s", errno_str));
        UA_close(fd);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Start listening */
    if(UA_listen(fd, MAXBACKLOG) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                           "Error listening on server socket: %s", errno_str));
        UA_close(fd);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCPListener(UA_Socket *socket, UA_UInt16 port, UA_String *customHostname, struct addrinfo *addrinfo,
                      UA_Logger logger) {
    UA_StatusCode retval;
    UA_Socket_internalData *internalData = (UA_Socket_internalData *)UA_malloc(sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)UA_malloc(sizeof(TcpSocketInternalData));
    if(implementationSpecificData == NULL) {
        UA_free(internalData);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    retval = UA_Socket_TCPListener_setup(internalData, implementationSpecificData, addrinfo);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(internalData);
        UA_free(implementationSpecificData);
        return retval;
    }

    implementationSpecificData->port = port;
    UA_ByteString_copy(customHostname, &implementationSpecificData->customHostname);

    socket->getFileDescriptor = UA_Socket_TCP_getFileDescriptor;
    socket->getDiscoveryUrl = UA_Socket_TCPListener_getDiscoveryUrl;
    socket->deleteMembers = UA_Socket_TCP_deleteMembers;
    socket->setPacketProcessingCallback = UA_Socket_TCP_setPacketProcessingCallback;

    internalData->completePacketCallback.callback = NULL;
    internalData->completePacketCallback.userData = NULL;
    internalData->timeoutCheckCallback = UA_Socket_TCPListener_timeoutCheckCallback;
    internalData->activityCallback = UA_Socket_TCPListener_activityCallback;
    internalData->logger = logger;

    internalData->implementationSpecificData = implementationSpecificData;
    socket->internalData = internalData;

    return retval;
}

UA_StatusCode
UA_Socket_TCPListener_create(UA_Socket_TCP_ConfigData *configData, UA_Socket_creationCallback creationCallback) {
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
        if(socket == NULL)
            goto cleanup;
        retval = UA_Socket_TCPListener(socket, configData->port, configData->customHostname, ai, configData->logger);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
        retval = creationCallback.callback(socket, creationCallback.userData);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

cleanup:
    if(socket != NULL && retval != UA_STATUSCODE_GOOD)
        UA_free(socket);

    if(internallyAllocated)
        UA_freeaddrinfo(ai);

    return retval;
}

static UA_StatusCode
UA_Socket_TCP_setupFDOptions(UA_Socket *socket, int fd) {
    const UA_Socket_internalData *const internalData = (const UA_Socket_internalData *const)socket->internalData;

    UA_StatusCode retval = UA_socket_set_nonblocking(fd);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Do not merge packets on the socket (disable Nagle's algorithm) */
    int dummy = 1;
    if(UA_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                     (const char *)&dummy, sizeof(dummy)) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_ERROR(internalData->logger, UA_LOGCATEGORY_NETWORK,
                         "Cannot set socket option TCP_NODELAY. Error: %s",
                         errno_str));
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }

    TcpSocketInternalData *implementationSpecificData =
        (TcpSocketInternalData *)internalData->implementationSpecificData;

    implementationSpecificData->fd = fd;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCP_acceptFrom(UA_Socket *socket, UA_Socket_creationCallback creationCallback) {
    if(socket == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const UA_Socket_internalData *const internalData = (const UA_Socket_internalData *const)socket->internalData;

    if(socket->getFileDescriptor == NULL) {
        UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                       "Socket does not support file descriptors. skipping");
        return UA_STATUSCODE_GOOD;
    }

    if(creationCallback.callback == NULL) {
        UA_LOG_ERROR(internalData->logger, UA_LOGCATEGORY_NETWORK, "No creationCallback set.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    struct sockaddr_storage remote;
    socklen_t remote_size = sizeof(remote);
    int newsockfd = UA_accept(socket->getFileDescriptor(socket), (struct sockaddr *)&remote, &remote_size);

    UA_LOG_TRACE(internalData->logger, UA_LOGCATEGORY_NETWORK,
                 "Listener Socket %i | New TCP connection on server socket %i",
                 newsockfd, socket->getFileDescriptor(socket));

#if defined(UA_getnameinfo)
    /* Get the peer name for logging */
    char remote_name[100];
    int res = UA_getnameinfo((struct sockaddr *)&remote,
                             sizeof(struct sockaddr_storage),
                             remote_name, sizeof(remote_name),
                             NULL, 0, NI_NUMERICHOST);
    if(res == 0) {
        UA_LOG_INFO(internalData->logger, UA_LOGCATEGORY_NETWORK,
                    "Listener Socket %i | New connection over TCP from %s",
                    (int)newsockfd, remote_name);
    } else {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_WARNING(internalData->logger, UA_LOGCATEGORY_NETWORK,
                                                "Listener Socket %i | New connection over TCP, "
                                                "getnameinfo failed with error: %s",
                                                newsockfd, errno_str));
    }
#else
    UA_LOG_INFO(layer->logger, UA_LOGCATEGORY_NETWORK,
                "Listener Socket %i | New connection over TCP",
                (int)newsockfd);
#endif

    UA_Socket *newSocket = (UA_Socket *)UA_malloc(sizeof(UA_Socket));

    UA_StatusCode retval = UA_Socket_TCP_setupInternal(newSocket, internalData->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(newSocket);
        UA_close(newsockfd);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }

    retval = UA_Socket_TCP_setupFDOptions(newSocket, newsockfd);
    if(retval != UA_STATUSCODE_GOOD) {
        newSocket->deleteMembers(newSocket);
        UA_free(newSocket);
        UA_close(newsockfd);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }

    return creationCallback.callback(newSocket, creationCallback.userData);
}

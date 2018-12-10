/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#include "ua_types_generated_handling.h"
#include "ua_sockets.h"
#include "ua_types.h"

#define MAXBACKLOG     100

typedef enum {
    UA_SOCKSTATE_NEW,
    UA_SOCKSTATE_OPEN,
    UA_SOCKSTATE_CLOSED,
} SocketState;

typedef struct {
    UA_Logger *logger;
    SocketState state;
    UA_DataSocketFactory *socketFactory;
} TcpSocketData;

static UA_StatusCode
tcp_sock_setDiscoveryUrl(UA_Socket *socket, in_port_t port, UA_ByteString *customHostname) {
    if(socket == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    TcpSocketData *const socketData = (TcpSocketData *const)socket->internalData;
    /* Get the discovery url from the hostname */
    UA_String du = UA_STRING_NULL;
    char discoveryUrlBuffer[256];
    char hostnameBuffer[256];
    if(customHostname != NULL) {
        du.length = (size_t)UA_snprintf(discoveryUrlBuffer, 255, "opc.tcp://%.*s:%d/",
                                        (int)customHostname->length,
                                        customHostname->data,
                                        ntohs(port));
        du.data = (UA_Byte *)discoveryUrlBuffer;
    } else {
        if(UA_gethostname(hostnameBuffer, 255) == 0) {
            du.length = (size_t)UA_snprintf(discoveryUrlBuffer, 255, "opc.tcp://%s:%d/",
                                            hostnameBuffer, ntohs(port));
            du.data = (UA_Byte *)discoveryUrlBuffer;
        } else {
            UA_LOG_ERROR(socketData->logger, UA_LOGCATEGORY_NETWORK, "Could not get the hostname");
        }
    }
    UA_LOG_INFO(socketData->logger, UA_LOGCATEGORY_NETWORK,
                "New TCP listener socket will listen on %.*s",
                (int)du.length, du.data);
    return UA_String_copy(&du, &socket->discoveryUrl);
}

static UA_StatusCode
tcp_sock_open(UA_Socket *sock) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;

    if(socketData->state != UA_SOCKSTATE_NEW) {
        UA_LOG_ERROR(socketData->logger, UA_LOGCATEGORY_NETWORK,
                     "Calling open on already open socket not supported");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(UA_listen((UA_SOCKET)sock->id, MAXBACKLOG) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(socketData->logger, UA_LOGCATEGORY_NETWORK,
                           "Error listening on server socket: %s", errno_str));
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    socketData->state = UA_SOCKSTATE_OPEN;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
tcp_sock_close(UA_Socket *sock) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;

    if(socketData->state == UA_SOCKSTATE_CLOSED)
        return UA_STATUSCODE_GOOD;

    UA_shutdown((UA_SOCKET)sock->id, UA_SHUT_RDWR);
    socketData->state = UA_SOCKSTATE_CLOSED;
    return UA_STATUSCODE_GOOD;
}

static UA_Boolean
tcp_sock_mayDelete(UA_Socket *sock) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;

    if(socketData->state == UA_SOCKSTATE_CLOSED)
        return true;

    return false;
}

static UA_StatusCode
tcp_sock_free(UA_Socket *sock) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;

    UA_ByteString_deleteMembers(&sock->discoveryUrl);

    UA_free(socketData);
    UA_free(sock);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
tcp_sock_activity(UA_Socket *sock) {
    if(sock == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;

    return socketData->socketFactory->buildSocket(socketData->socketFactory, sock);
}

static UA_StatusCode
tcp_sock_send(UA_Socket *sock, UA_ByteString *data) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;
    UA_LOG_ERROR(socketData->logger, UA_LOGCATEGORY_NETWORK,
                 "Sending is not supported on listener sockets");
    // TODO: Can we support sending here? does it make sense at all?
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static UA_StatusCode
tcp_sock_getSendBuffer(UA_Socket *sock, UA_ByteString **p_buffer) {
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;
    UA_LOG_ERROR(socketData->logger, UA_LOGCATEGORY_NETWORK,
                 "Getting a send buffer is not supported on listener sockets");
    // TODO: see above
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static UA_StatusCode
tcp_sock_set_func_pointers(UA_Socket *socket) {
    socket->open = tcp_sock_open;
    socket->close = tcp_sock_close;
    socket->mayDelete = tcp_sock_mayDelete;
    socket->free = tcp_sock_free;
    socket->activity = tcp_sock_activity;
    socket->send = tcp_sock_send;
    socket->getSendBuffer = tcp_sock_getSendBuffer;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_TCP_ListenerSocketFromAddrinfo(struct addrinfo *addrinfo,
                                  UA_DataSocketFactory *dataSocketFactory,
                                  UA_Logger *logger,
                                  UA_ByteString *customHostname,
                                  UA_Socket **p_socket) {
    UA_StatusCode retval;
    if(logger == NULL || dataSocketFactory == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_Socket *sock = (UA_Socket *)UA_malloc(sizeof(UA_Socket));
    if(sock == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memset(sock, 0, sizeof(UA_Socket));

    sock->isListener = true;
    sock->internalData = (TcpSocketData *)UA_malloc(sizeof(TcpSocketData));
    if(sock->internalData == NULL) {
        UA_free(sock);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    TcpSocketData *const socketData = (TcpSocketData *const)sock->internalData;
    memset(socketData, 0, sizeof(TcpSocketData));
    socketData->logger = logger;
    socketData->socketFactory = dataSocketFactory;
    socketData->state = UA_SOCKSTATE_NEW;

    in_port_t port;
    if(addrinfo->ai_addr->sa_family == AF_INET)
        port = (((struct sockaddr_in *)addrinfo->ai_addr)->sin_port);
    else
        port = (((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_port);
    tcp_sock_setDiscoveryUrl(sock, port, customHostname);

    UA_SOCKET socket_fd = UA_socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(socket_fd == UA_INVALID_SOCKET) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                       "Error opening the listener socket");
        goto error;
    }
    sock->id = (UA_UInt64)socket_fd;

    int optval = 1;
#if UA_IPV6
    if(addrinfo->ai_family == AF_INET6 &&
       UA_setsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                     (const char *)&optval, sizeof(optval)) == -1) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set an IPv6 socket to IPv6 only");
        goto error;
    }
#endif
    if(UA_setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&optval, sizeof(optval)) == -1) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                       "Could not make the socket reusable");
        goto error;
    }

    if(UA_socket_set_nonblocking(socket_fd) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set the server socket to nonblocking");
        goto error;
    }

    if(UA_bind(socket_fd, addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                           "Error binding a server socket: %s", errno_str));
        goto error;
    }

    retval = tcp_sock_set_func_pointers(sock);
    if(retval != UA_STATUSCODE_GOOD) {
        goto error;
    }

    *p_socket = sock;

    UA_LOG_TRACE(logger, UA_LOGCATEGORY_NETWORK,
                 "Created new listener socket %p", (void *)sock);
    return UA_STATUSCODE_GOOD;

error:
    if(socket_fd != UA_INVALID_SOCKET)
        UA_close(socket_fd);
    UA_free(sock->internalData);
    UA_free(sock);
    return UA_STATUSCODE_BADINTERNALERROR;
}


UA_StatusCode
UA_TCP_ListenerSockets(UA_UInt32 port,
                       UA_DataSocketFactory *dataSocketFactory,
                       UA_Logger *logger,
                       UA_ByteString *customHostname,
                       UA_Socket **p_sockets[]) {

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(dataSocketFactory == NULL || logger == NULL || p_sockets == NULL) {
        return retval;
    }

    char portno[6];
    UA_snprintf(portno, 6, "%d", port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;
    if(UA_getaddrinfo(NULL, portno, &hints, &res) != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* There might be serveral addrinfos (for different network cards,
     * IPv4/IPv6). Add a server socket for all of them. */
    size_t numSockets = 0;
    for(struct addrinfo *ai = res; numSockets < FD_SETSIZE && ai != NULL; ai = ai->ai_next, ++numSockets);
    UA_Socket **sockets = (UA_Socket **)UA_malloc(sizeof(UA_Socket *));
    if(sockets == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    for(struct addrinfo *ai = res; numSockets > 0 && ai != NULL; --numSockets, ai = ai->ai_next) {
        retval = UA_TCP_ListenerSocketFromAddrinfo(ai, dataSocketFactory, logger,
                                                   customHostname, &sockets[numSockets - 1]);
    }
    UA_freeaddrinfo(res);

    return retval;
}

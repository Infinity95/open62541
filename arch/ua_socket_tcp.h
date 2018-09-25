#ifndef OPEN62541_UA_SOCKET_TCP_H
#define OPEN62541_UA_SOCKET_TCP_H

#include "ua_plugin_socket.h"

typedef struct {
    UA_UInt16 port;
    UA_String *customHostname;
    UA_Logger logger;
    struct addrinfo *addrinfo;
} UA_Socket_TCP_ConfigData;

UA_StatusCode
UA_Socket_TCP(UA_Socket *socket, UA_Logger logger);

UA_StatusCode
UA_Socket_TCPListener(UA_Socket *socket, UA_UInt16 port, UA_String *customHostname, struct addrinfo *addrinfo,
                      UA_Logger logger);

/**
 * Creates one or more TCP listener sockets. If the addrinfo struct in the config data
 * is empty, the function will fetch all applicable addrinfos and create a socket for
 * each of them.
 * Otherwise the supplied addrinfo struct (chain) is used.
 * For each socket that is created, the creationCallback function is called with
 * the new socket and the userData as parameters.
 * This makes it easy to add the newly created sockets to for example a list.
 *
 * \param configData
 * \param creationCallback
 * \param userData
 * \return
 */
UA_StatusCode
UA_Socket_TCPListener_create(UA_Socket_TCP_ConfigData *configData, UA_Socket_creationCallback creationCallback,
                             void *userData);

#endif //OPEN62541_UA_SOCKET_TCP_H

#ifndef OPEN62541_UA_SOCKET_TCP_H
#define OPEN62541_UA_SOCKET_TCP_H

#include "ua_plugin_socket.h"


UA_StatusCode
UA_Socket_TCP(UA_Socket *socket, UA_Logger logger);

UA_StatusCode
UA_Socket_TCPListener(UA_Socket *socket, UA_Logger logger);

#endif //OPEN62541_UA_SOCKET_TCP_H

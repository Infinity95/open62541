#include "ua_plugin_socket.h"
#include "ua_socket_tcp.h"

static UA_StatusCode
UA_Socket_TCP_activityCallback(void) {

}

static UA_StatusCode
UA_Socket_TCP_init(UA_Socket *socket) {
    UA_Socket_internalData *internalData = UA_malloc(sizeof(UA_Socket_internalData));
    if(internalData == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    internalData->activityCallback = UA_Socket_TCP_activityCallback;

    socket->internalData = internalData;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Socket_TCP_deleteMembers(UA_Socket *socket) {
    UA_free(socket->internalData);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Socket_TCP(UA_Socket *socket) {
    socket->init = UA_Socket_TCP_init;
    socket->deleteMembers = UA_Socket_TCP_deleteMembers;
    return UA_STATUSCODE_GOOD;
}

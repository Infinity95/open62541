//
// Created by giraud on 07.09.18.
//

#include "ua_network_managers.h"
#include "../deps/queue.h"

typedef struct SocketListEntry {
    UA_Socket *socket;
    LIST_ENTRY(SocketListEntry) pointers;
} SocketListEntry;

typedef struct {
    UA_Logger logger;
    LIST_HEAD(, SocketListEntry) sockets;
    fd_set activeSocketFDs;
    UA_Int32 highestFD;
} NetworkManagerData;


static UA_StatusCode
UA_SelectBasedNetworkManager_init(UA_NetworkManager *networkManager, UA_Logger logger) {
    networkManager->internalData = UA_malloc(sizeof(NetworkManagerData));
    if(networkManager->internalData == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    NetworkManagerData *networkManagerData = (NetworkManagerData *)networkManager->internalData;

    networkManagerData->logger = logger;

    return UA_STATUSCODE_GOOD;
}

static UA_Int32
markFileDescriptorsToSelect(NetworkManagerData *networkManagerData) {
    FD_ZERO(&networkManagerData->activeSocketFDs);
    UA_Int32 highestfd = 0;

    SocketListEntry *e;
    LIST_FOREACH(e, &networkManagerData->sockets, pointers) {
        if(e->socket->getFileDescriptor == NULL) {
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket does not support select. Skipping");
            continue;
        }
        int fd = e->socket->getFileDescriptor(e->socket);
        UA_fd_set(fd, &networkManagerData->activeSocketFDs);
        if((UA_Int32)fd > highestfd)
            highestfd = (UA_Int32)fd;
    }

    return highestfd;
}

static UA_StatusCode
UA_SelectBasedNetworkManager_listen(UA_NetworkManager *networkManager, UA_Int32 timeout) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    NetworkManagerData *networkManagerData = (NetworkManagerData *)networkManager->internalData;

    fd_set fdset = networkManagerData->activeSocketFDs;
    fd_set errset = networkManagerData->activeSocketFDs;
    struct timeval tmptv = {0, timeout * 1000};
    int active_fds = UA_select(networkManagerData->highestFD + 1, &fdset, NULL, &errset, &tmptv);
    if(active_fds < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket select failed with %s", errno_str));
        // we will retry, so do not return bad
        return UA_STATUSCODE_GOOD;
    }

    SocketListEntry *socketListEntry, *e_tmp;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    LIST_FOREACH_SAFE(socketListEntry, &networkManagerData->sockets, pointers, e_tmp) {
        // break because all active fds have already been processed.
        if(active_fds <= 0)
            break;

        UA_Socket *socket = socketListEntry->socket;
        UA_Socket_internalData *socket_internalData = (UA_Socket_internalData *)socket->internalData;
        if(socket->getFileDescriptor == NULL) {
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket does not support select. Skipping");
            continue;
        }
        int fd = socket->getFileDescriptor(socket);
        if(socket_internalData->timeoutCheckCallback(now) != UA_STATUSCODE_GOOD) {
            LIST_REMOVE(socketListEntry, pointers);
            continue;
        }

        if(!UA_fd_isset(fd, &errset) && !UA_fd_isset(fd, &fdset))
            continue;

        UA_LOG_TRACE(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                     "Connection %i | Activity on the socket", fd);

        retval = socket_internalData->activityCallback(socket);
        --active_fds;
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                         "Encountered an error while processing activity callback of socket with fd %i",
                         fd);
            return retval;
        }
    }

    return retval;
}

static UA_StatusCode
UA_SelectBasedNetworkManager_registerSocket(UA_NetworkManager *networkManager, UA_Socket *socket) {

    NetworkManagerData *const networkManagerData = (NetworkManagerData *)networkManager->internalData;

    SocketListEntry *newSocketEntry = (SocketListEntry *)UA_malloc(sizeof(SocketListEntry));
    if(newSocketEntry == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    newSocketEntry->socket = socket;
    LIST_INSERT_HEAD(&networkManagerData->sockets, newSocketEntry, pointers);

    networkManagerData->highestFD = markFileDescriptorsToSelect(networkManagerData);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_SelectBasedNetworkManager_deleteMembers(UA_NetworkManager *networkManager) {
    // clean up connections

    UA_free(networkManager->internalData);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SelectBasedNetworkManager(UA_NetworkManager *networkManager) {

    networkManager->init = UA_SelectBasedNetworkManager_init;
    networkManager->listen = UA_SelectBasedNetworkManager_listen;
    networkManager->registerSocket = UA_SelectBasedNetworkManager_registerSocket;
    networkManager->deleteMembers = UA_SelectBasedNetworkManager_deleteMembers;
    return UA_STATUSCODE_GOOD;
}

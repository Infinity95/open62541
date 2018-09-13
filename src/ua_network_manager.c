//
// Created by giraud on 07.09.18.
//

#include "ua_network_manager.h"
#include "../deps/queue.h"

typedef struct SocketListEntry {
    UA_Socket socket;
    LIST_ENTRY(SocketListEntry) pointers;
} SocketListEntry;

typedef struct {
    UA_Logger logger;
    LIST_HEAD(, SocketListEntry) sockets;
} NetworkManagerData;

UA_StatusCode
UA_NetworkManager_addSocket(UA_NetworkManager *networkManager,
                            UA_Socket socket) {


    return UA_STATUSCODE_GOOD;
}


UA_StatusCode
UA_NetworkManager_init(UA_NetworkManager *networkManager, UA_Logger logger) {
    networkManager->internalData = UA_malloc(sizeof(NetworkManagerData));
    if(networkManager->internalData == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    NetworkManagerData *networkManagerData = (NetworkManagerData *)networkManager->internalData;

    networkManagerData->logger = logger;

    return UA_STATUSCODE_GOOD;
}

static UA_Int32
markFileDescriptorsToSelect(NetworkManagerData *networkManagerData, fd_set *fdset) {
    FD_ZERO(fdset);
    UA_Int32 highestfd = 0;

    SocketListEntry *e;
    LIST_FOREACH(e, &networkManagerData->sockets, pointers) {
        if(e->socket.getFileDescriptor == NULL) {
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket does not support select. Skipping");
            continue;
        }
        int fd = e->socket.getFileDescriptor();
        UA_fd_set(fd, fdset);
        if((UA_Int32)fd > highestfd)
            highestfd = (UA_Int32)fd;
    }

    return highestfd;
}

UA_StatusCode
UA_NetworkManager_process(UA_NetworkManager *networkManager, UA_Int32 timeout) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    NetworkManagerData *networkManagerData = (NetworkManagerData *)networkManager->internalData;
    /* Listen on open sockets (including the server) */
    fd_set fdset, errset;
    UA_Int32 highestfd = markFileDescriptorsToSelect(networkManagerData, &fdset);
    markFileDescriptorsToSelect(networkManagerData, &errset);
    struct timeval tmptv = {0, timeout * 1000};
    if(UA_select(highestfd + 1, &fdset, NULL, &errset, &tmptv) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket select failed with %s", errno_str));
        // we will retry, so do not return bad
        return UA_STATUSCODE_GOOD;
    }

    SocketListEntry *socketListEntry, *e_tmp;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    LIST_FOREACH_SAFE(socketListEntry, &networkManagerData->sockets, pointers, e_tmp) {
        UA_Socket *socket = &socketListEntry->socket;
        if(socket->getFileDescriptor == NULL) {
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Socket does not support select. Skipping");
            continue;
        }
        int fd = socket->getFileDescriptor();
        if(socket->timeoutCheckCallback() != UA_STATUSCODE_GOOD) {
            LIST_REMOVE(socketListEntry, pointers);
            continue;
        }

        if(!UA_fd_isset(fd, &errset) && !UA_fd_isset(fd, &fdset))
            continue;

        UA_LOG_TRACE(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                     "Connection %i | Activity on the socket", fd);

        retval = socket->activityCallback();
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(networkManagerData->logger, UA_LOGCATEGORY_NETWORK,
                           "Encountered an error while processing activity callback of socket with fd %i",
                           fd);
            // TODO: Ignore the error, or do we want to abort processing and return?
            retval = UA_STATUSCODE_GOOD; // Ignore error.
        }
    }

    return retval;
}

UA_StatusCode
UA_NetworkManager_deleteMembers(UA_NetworkManager *networkManager) {
    // clean up connections

    UA_free(networkManager->internalData);
    return UA_STATUSCODE_GOOD;
}

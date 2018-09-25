/**
 * EXPERIMENTAL Network Manager
 */

#ifndef OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H
#define OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H

#include "ua_types.h"
#include "ua_plugin_log.h"
#include "ua_plugin_socket.h"

struct UA_NetworkManager;
typedef struct UA_NetworkManager UA_NetworkManager;

struct UA_NetworkManager {
    void *internalData;

    UA_StatusCode (*init)(UA_NetworkManager *networkManager, UA_Logger logger);

    /**
     * Cleans up the internal data.
     *
     * @param networkManager
     * @return
     */
    UA_StatusCode (*deleteMembers)(UA_NetworkManager *networkManager);

    /**
     * Registers a socket in the network manager. Whenever the socket is ready for receiveing,
     * its activityCallback function is called.
     *
     * @param networkManager
     * @param socket
     * @return
     */
    UA_StatusCode (*registerSocket)(UA_NetworkManager *networkManager,
                                    UA_Socket *socket);

    /**
     * Performs one iteration of listening for activity on any of the registered sockets.
     * If a socket has a data waiting to be processed, the activity callback of the socket is called.
     * If an error occurs during processing, the function will immediately return with an error code.
     *
     * @param networkManager
     * @param timeout
     * @return
     */
    UA_StatusCode (*listen)(UA_NetworkManager *networkManager,
                            UA_Int32 timeout);

    /**
     * Once a socket has received a complete packet, the process callback, the buffer and user data
     * are enqueued into a processing queue. With each call to processSocketCallbacks the queue
     * is emptied and all pending packets are processed.
     *
     * \param networkManager
     * \return
     */
    UA_StatusCode (*processSocketCallbacks)(UA_NetworkManager *networkManager);
};

/**
 * This scruct contains internal function pointers that are only used by the socket and network manager.
 * It defines the api between network manager and socket.
 */
typedef struct {
    UA_StatusCode (*activityCallback)(UA_Socket *socket);

    UA_StatusCode (*timeoutCheckCallback)(UA_DateTime now);

    UA_Socket_processCompletePacketCallback completePacketCallback;

    UA_Logger logger;

    UA_NetworkManager *networkManager;

    void *implementationSpecificData;
} UA_Socket_internalData;

#endif //OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2019 (c) fortiss (Author: Stefan Profanter)
 */


#include "custom_memory_manager.h"

#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>
#include <open62541/types.h>

#include "ua_server_internal.h"
#include "testing_socket.h"
#define RECEIVE_BUFFER_SIZE 65535

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (!UA_memoryManager_setLimitFromLast4Bytes(data, size))
        return 0;
    size -= 4;

    UA_Server *server = UA_Server_new();
    if(!server) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Could not create server instance using UA_Server_new");
        return 0;
    }

    UA_StatusCode retval = UA_ServerConfig_setDefault(UA_Server_getConfig(server));
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Could not set the server config");
        return 0;
    }

    UA_Socket sock = createDummySocket(nullptr);
    UA_Connection *connection = nullptr;
    retval = UA_Connection_new(server->config.connectionConfig, &sock,
                               nullptr, UA_Log_Stdout, &connection);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Could not create new connection");
        return 0;
    }
    connection->chunkCallback.function = (UA_ProcessChunkCallbackFunction)UA_Server_processChunk;
    connection->chunkCallback.callbackContext = server;
    sock.context = connection;

    // we need to copy the message because it will be freed in the processing function
    UA_ByteString msg{};
    UA_ByteString_init(&msg);
    retval = UA_ByteString_allocBuffer(&msg, size);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "Could not allocate message buffer");
        return 0;
    }
    memcpy(msg.data, data, size);

    UA_Connection_assembleChunks(&msg, &sock);
    // if we got an invalid chunk, the message is not deleted, so delete it here
    UA_ByteString_deleteMembers(&msg);
    UA_Server_run_shutdown(server);
    UA_Connection_close(connection);
    UA_Connection_free(connection);
    UA_Server_delete(server);
    return 0;
}

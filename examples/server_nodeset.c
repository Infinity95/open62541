/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <signal.h>
#include <stdlib.h>
#include "open62541.h"

/* Files nodeset.h and nodeset.c are created from server_nodeset.xml in the
 * /src_generated directory by CMake */
#include "nodeset.h"

UA_Boolean running = true;

static void stopHandler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "received ctrl-c");
    running = false;
}

int main(int argc, char** argv) {
    signal(SIGINT, stopHandler); /* catches ctrl-c */

    /* initialize the server */
    UA_ServerConfig config = UA_ServerConfig_standard;
    UA_ServerNetworkLayer nl = UA_ServerNetworkLayerTCP(UA_ConnectionConfig_standard, 16664);
    config.networkLayers = &nl;
    config.networkLayersSize = 1;
    UA_Server *server = UA_Server_new(config);

    /* create nodes from nodeset */
    if (nodeset(server) != UA_STATUSCODE_GOOD) {
		UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Namespace index for generated "
                     "nodeset does not match. The call to the generated method has to be "
                     "before any other namespace add calls.");
		UA_Server_delete(server);
		nl.deleteMembers(&nl);
		return (int)UA_STATUSCODE_BADUNEXPECTEDERROR;
	}

    /* start server */
    UA_StatusCode retval = UA_Server_run(server, &running);

    /* ctrl-c received -> clean up */
    UA_Server_delete(server);
    nl.deleteMembers(&nl);
    return (int)retval;
}

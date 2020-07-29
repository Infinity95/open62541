#include "../fuzz/custom_memory_manager.h"

#include <pthread.h>

#include <open62541/plugin/log_stdout.h>
#include <open62541/server_config_default.h>
#include <open62541/types.h>
#include <aft/FuzzTestCase.hpp>
#include <utility>

#include "ua_server_internal.h"

#define RECEIVE_BUFFER_SIZE 65535

void del_server(UA_Server *s) {
    UA_Server_delete(s);
}

class SockClient {
private:
    int fd{-1};
public:
    SockClient() = default;

    ~SockClient() {
        if(fd != -1) {
            close(fd);
            fd = -1;
        }
    }

    void connect(UA_UInt16 port) {
        if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT,
                         "Could not create socket");
            throw std::system_error{errno, std::system_category(), "socket()"};
        }
        struct sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int status = ::connect(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        if(status < 0) {
            throw std::system_error{errno, std::system_category(), "connect()"};
        }
    }

    void sendAll(const uint8_t *data, size_t size) const {
        /* Send the full buffer. This may require several calls to send */
        size_t nWritten = 0;
        int flags = MSG_NOSIGNAL;
        do {
            ssize_t n = 0;
            do {
                size_t bytes_to_send = size - nWritten;
                n = send(fd, (const char *) data + nWritten, bytes_to_send, flags);
                if(n < 0 && UA_ERRNO != UA_INTERRUPTED && UA_ERRNO != UA_AGAIN) {
                    throw std::system_error{errno, std::system_category(), "send()"};
                }
            } while(n < 0);
            nWritten += (size_t) n;
        } while(nWritten < size);
    }
};

class Open62541FuzzTest : public FuzzTestCase {
private:
    std::unique_ptr<UA_Server, void (*)(UA_Server *)> server{nullptr, del_server};
    UA_UInt16 server_port{0};
    SockClient sock{};
public:
    explicit Open62541FuzzTest(std::filesystem::path inputChainDir) : FuzzTestCase(std::move(inputChainDir)) {}

    ~Open62541FuzzTest() override = default;

    int setup() override {
        server.reset(UA_Server_new());

        UA_ServerConfig *config = UA_Server_getConfig(server.get());
        UA_StatusCode retval = UA_ServerConfig_setMinimal(config, server_port, nullptr);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                         "Could not create server instance using UA_Server_new. %s", UA_StatusCode_name(retval));
            UA_Server_delete(server.get());
            return EXIT_FAILURE;
        }

        // Enable the mDNS announce and response functionality
        config->mdnsEnabled = true;

        config->mdnsConfig.mdnsServerName = UA_String_fromChars("Sample Multicast Server");

        retval = UA_Server_run_startup(server.get());
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                         "Could not run UA_Server_run_startup. %s", UA_StatusCode_name(retval));
            UA_Server_delete(server.get());
            return EXIT_FAILURE;
        }

        // Iterate once to initialize the TCP connection. Otherwise the connect below may come before the server is up.
        UA_Server_run_iterate(server.get(), true);

        server_port = server->config.networkLayers[0].getPort(&server->config.networkLayers[0]);
        sock.connect(server_port);
        return EXIT_SUCCESS;
    }

    int input(const std::vector<uint8_t> &input) override {
        const auto *data = input.data();
        auto size = input.size();
        if(UA_memoryManager_setLimitFromLast4Bytes(data, size) == 0) {
            return EXIT_SUCCESS;
        }
        size -= 4;

        sock.sendAll(data, size);

        return 0;
    }

    int process() override {
        for(int i = 0; i < 10; ++i)
            UA_Server_run_iterate(server.get(), false);
        return EXIT_SUCCESS;
    }

    void teardown() override {
        process();
        UA_Server_run_shutdown(server.get());
        UA_memoryManager_setLimit(static_cast<unsigned long long int>(-1));
    }
};

std::unique_ptr<FuzzTestCase>
getTestCase() {
    std::unique_ptr<FuzzTestCase> ptr = std::make_unique<Open62541FuzzTest>("input_chain");
    return ptr;
}

//static void *serverLoop(void *server_ptr) {
//    UA_Server *server = (UA_Server*) server_ptr;
//
//    while (running) {
//        UA_Server_run_iterate(server, false);
//    }
//    return NULL;
//}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
extern "C" int
bla(const uint8_t *data, size_t size) {
    return 0;
//    UA_Server *server = UA_Server_new();
//    if(!server) {
//        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                     "Could not create server instance using UA_Server_new");
//        return EXIT_FAILURE;
//    }
//
//    UA_ServerConfig *config = UA_Server_getConfig(server);
//    UA_StatusCode retval = UA_ServerConfig_setMinimal(config, SERVER_PORT, NULL);
//    if (retval != UA_STATUSCODE_GOOD) {
//        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                     "Could not create server instance using UA_Server_new. %s", UA_StatusCode_name(retval));
//        UA_Server_delete(server);
//        return EXIT_FAILURE;
//    }
//
//    // Enable the mDNS announce and response functionality
//    config->mdnsEnabled = true;
//
//    config->mdnsConfig.mdnsServerName = UA_String_fromChars("Sample Multicast Server");
//
//    retval = UA_Server_run_startup(server);
//    if(retval != UA_STATUSCODE_GOOD) {
//        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                     "Could not run UA_Server_run_startup. %s", UA_StatusCode_name(retval));
//        UA_Server_delete(server);
//        return EXIT_FAILURE;
//    }
//
//    if (!UA_memoryManager_setLimitFromLast4Bytes(data, size)) {
//        UA_Server_run_shutdown(server);
//        UA_Server_delete(server);
//        return EXIT_SUCCESS;
//    }
//    size -= 4;
//
//    // Iterate once to initialize the TCP connection. Otherwise the connect below may come before the server is up.
//    UA_Server_run_iterate(server, true);
//
//    pthread_t serverThread;
//    int rc = pthread_create(&serverThread, NULL, serverLoop, (void *)server);
//    if (rc){
//
//        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
//                     "return code from pthread_create() is %d", rc);
//
//        UA_Server_run_shutdown(server);
//        UA_Server_delete(server);
//        return -1;
//    }
//
//    int retCode = EXIT_SUCCESS;
//
//    int sockfd = 0;
//    {
//        // create a client and write to localhost TCP server
//
//        if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
//        {
//            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT,
//                         "Could not create socket");
//            retCode = EXIT_FAILURE;
//        } else {
//
//            struct sockaddr_in serv_addr;
//            serv_addr.sin_family = AF_INET;
//            serv_addr.sin_port = htons(SERVER_PORT);
//            serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//
//            int status = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
//            if (status >= 0) {
//                if (write(sockfd, data, size) != size) {
//                    UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT,
//                                 "Did not write %lu bytes", (long unsigned)size);
//                    retCode = EXIT_FAILURE;
//                }
//            } else {
//                UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT,
//                             "Could not connect to server: %s", strerror(errno));
//                retCode = EXIT_FAILURE;
//            }
//        }
//
//    }
//    running = false;
//    void *status;
//    pthread_join(serverThread, &status);
//
//    // Process any remaining data. Just repeat a few times to empty all the buffered bytes
//    for (size_t i=0; i<5; i++) {
//        UA_Server_run_iterate(server, false);
//    }
//    close(sockfd);
//
//
//    UA_Server_run_shutdown(server);
//    UA_Server_delete(server);
//
//    return retCode;
}

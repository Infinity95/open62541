/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018 Fraunhofer IOSB (Author: Lukas Meling)
 */

#include <include/open62541/plugin/networking/sockets.h>
#include "ua_mqtt_adapter.h"
#include "../../deps/mqtt-c/mqtt.h"
#include "open62541/plugin/log_stdout.h"
#include "open62541/util.h"

/* forward decl for callback */
void
publish_callback(void **, struct mqtt_response_publish *);

static UA_StatusCode
mqtt_socket_created(UA_Socket *socket) {
    UA_PubSubChannelDataMQTT *channelData = (UA_PubSubChannelDataMQTT *)socket->application;
    channelData->socket = socket;
    UA_socket_set_nonblocking((UA_SOCKET)socket->id);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
connectMqtt(UA_PubSubChannelDataMQTT *channelData) {
    if(channelData == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    /* Get address and replace mqtt with tcp
     * because we use a tcp UA_ClientConnectionTCP for mqtt */
    UA_NetworkAddressUrlDataType address = channelData->address;

    UA_String hostname, path;
    UA_UInt16 networkPort;
    if(UA_parseEndpointUrl(&address.url, &hostname, &networkPort, &path) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "MQTT PubSub Connection creation failed. Invalid URL.");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    /* Build the url, replace mqtt with tcp */
    UA_STACKARRAY(UA_Byte, addressAsChar, 10 + (sizeof(char) * path.length));
    memcpy((char*)addressAsChar, "opc.tcp://", 10);
    memcpy((char*)&addressAsChar[10],(char*)path.data, path.length);
    address.url.data = addressAsChar;
    address.url.length = 10 + (sizeof(char) * path.length);

    /* check if buffers are correct */
    if(!(channelData->mqttRecvBufferSize > 0 && channelData->mqttRecvBuffer != NULL
         && channelData->mqttSendBufferSize > 0 && channelData->mqttSendBuffer != NULL)) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "MQTT PubSub Connection creation failed. No Mqtt buffer allocated.");
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    }

    /* Config with default parameters */
    UA_ClientSocketConfig conf;
    memset(&conf, 0, sizeof(UA_ClientSocketConfig));
    // TODO: Make these values configurable from the outside.
    // TODO: Integrate mqtt pubsub with the networkmanager.
    conf.baseConfig.sendBufferSize = 1000;
    conf.baseConfig.recvBufferSize = 2000;
//    conf.maxMessageSize = 1000;
//    conf.maxChunkCount = 1;

    UA_StatusCode retval = UA_TCP_ClientDataSocket(channelData, &conf, address.url, mqtt_socket_created);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK,
                     "PubSub MQTT: Connection creation failed. Tcp connection failed!");
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }
    retval = channelData->socket->open(channelData->socket);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK,
                     "PubSub MQTT: Failed to open the socket.");
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);

        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    fd_set writefdset;
    FD_ZERO(&writefdset);

    UA_fd_set((UA_SOCKET)channelData->socket->id, &writefdset);

    UA_UInt32 timeout = 1000;
    long int secs = (long int)timeout / 1000;
    long int microsecs = ((long int)timeout * 1000) % 1000000;
    struct timeval tmptv = {secs, microsecs};

    int resultsize = UA_select((UA_Int32)(channelData->socket->id + 1), NULL, &writefdset, NULL, &tmptv);
    if(resultsize == 1) {
        UA_Boolean writeActivity = UA_fd_isset((UA_SOCKET)channelData->socket->id, &writefdset);
        retval = channelData->socket->activity(channelData->socket, UA_FALSE, writeActivity);
        if (retval != UA_STATUSCODE_GOOD) {
            channelData->socket->close(channelData->socket);
            channelData->socket->clean(channelData->socket);
            UA_free(channelData->socket);
            return retval;
        }
    }
    if(resultsize == 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK, "Socket select timed out");
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        return UA_STATUSCODE_BADTIMEOUT;
    }
    if(resultsize == -1) {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK,
                                              "Socket select failed with %s", errno_str));
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* calloc mqtt_client */
    struct mqtt_client *client = (struct mqtt_client *)UA_calloc(1, sizeof(struct mqtt_client));
    if(!client) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);

        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. Out of memory.");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* save reference */
    channelData->mqttClient = client;

    /* create custom sockethandle */
    struct my_custom_socket_handle *handle =
        (struct my_custom_socket_handle *)UA_calloc(1, sizeof(struct my_custom_socket_handle));
    if(!handle) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        UA_free(client);

        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. Out of memory.");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    handle->client = client;
    handle->connection = channelData->socket;

    /* init mqtt client struct with buffers and callback */
    enum MQTTErrors mqttErr = mqtt_init(client, handle, channelData->mqttSendBuffer, channelData->mqttSendBufferSize,
                                        channelData->mqttRecvBuffer, channelData->mqttRecvBufferSize, publish_callback);
    if(mqttErr != MQTT_OK) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        UA_free(client);

        const char *errorStr = mqtt_error_str(mqttErr);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. MQTT error: %s",
                     errorStr);
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    /* Init custom data for subscribe callback function:
     * A reference to the channeldata will be available in the callback.
     * This is used to call the user callback channelData.callback */
    client->publish_response_callback_state = channelData;

    /* Convert clientId UA_String to char* null terminated */
    char* clientId = (char*)calloc(1,channelData->mqttClientId->length + 1);
    if(!clientId) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. Out of memory.");
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        UA_free(client);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memcpy(clientId, channelData->mqttClientId->data, channelData->mqttClientId->length);

    char *username = NULL;
    if (channelData->mqttUsername.length > 0) {
        /* Convert username UA_String to char* null terminated */
        username = (char*)calloc(1,channelData->mqttUsername.length + 1);
        if(!username){
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. Out of memory.");
            UA_free(channelData->connection);
            UA_free(client);
            UA_free(clientId);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(username, channelData->mqttUsername.data, channelData->mqttUsername.length);
    }

    char *password = NULL;
    if (channelData->mqttPassword.length > 0) {
        /* Convert password UA_String to char* null terminated */
        password = (char*)calloc(1,channelData->mqttPassword.length + 1);
        if(!password){
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: Connection creation failed. Out of memory.");
            UA_free(channelData->connection);
            UA_free(client);
            UA_free(clientId);
            UA_free(username);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(password, channelData->mqttPassword.data, channelData->mqttPassword.length);
    }

    /* Connect mqtt with socket fd of networktcp  */
    mqttErr = mqtt_connect(client, clientId, NULL, NULL, 0, username, password, 0, 400);
    UA_free(clientId);
    UA_free(username);
    UA_free(password);
    if(mqttErr != MQTT_OK) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        UA_free(client);

        const char *errorStr = mqtt_error_str(mqttErr);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "%s", errorStr);
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    /* sync the first mqtt packets in the buffer to send connection request.
       After that yield must be called frequently to exchange mqtt messages. */
    UA_StatusCode ret = yieldMqtt(channelData, 100);
    if(ret != UA_STATUSCODE_GOOD) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        UA_free(client);
        return ret;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
disconnectMqtt(UA_PubSubChannelDataMQTT* channelData) {
    if(channelData == NULL) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    channelData->callback = NULL;
    struct mqtt_client *client = (struct mqtt_client *)channelData->mqttClient;
    if(client) {
        mqtt_disconnect(client);
        yieldMqtt(channelData, 10);
        UA_free(client->socketfd);
    }
    if(channelData->socket != NULL) {
        channelData->socket->close(channelData->socket);
        channelData->socket->clean(channelData->socket);
        UA_free(channelData->socket);
        channelData->socket = NULL;
    }
    UA_free(channelData->mqttRecvBuffer);
    channelData->mqttRecvBuffer = NULL;
    UA_free(channelData->mqttSendBuffer);
    channelData->mqttSendBuffer = NULL;
    UA_free(channelData->mqttClient);
    channelData->mqttClient = NULL;
    return UA_STATUSCODE_GOOD;
}

void
publish_callback(void** channelDataPtr, struct mqtt_response_publish *published)
{
    if(channelDataPtr != NULL){
        UA_PubSubChannelDataMQTT *channelData = (UA_PubSubChannelDataMQTT*)*channelDataPtr;
        if(channelData != NULL){
            if(channelData->callback != NULL){
                //Setup topic
                UA_ByteString *topic = UA_ByteString_new();
                if(!topic) return;
                UA_ByteString *msg = UA_ByteString_new();  
                if(!msg) return;
                
                /* memory for topic */
                UA_StatusCode ret = UA_ByteString_allocBuffer(topic, published->topic_name_size);
                if(ret){
                    UA_free(topic);
                    UA_free(msg);
                    return;
                }
                /* memory for message */
                ret = UA_ByteString_allocBuffer(msg, published->application_message_size);
                if(ret){
                    UA_ByteString_delete(topic);
                    UA_free(msg);
                    return;
                }
                /* copy topic and msg, call the cb */
                memcpy(topic->data, published->topic_name, published->topic_name_size);
                memcpy(msg->data, published->application_message, published->application_message_size);
                channelData->callback(msg, topic);
            }
        }
    }  
}

UA_StatusCode
subscribeMqtt(UA_PubSubChannelDataMQTT* channelData, UA_String topic, UA_Byte qos){
    if(channelData == NULL || topic.length == 0){
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    struct mqtt_client* client = (struct mqtt_client*)channelData->mqttClient;
    
    UA_STACKARRAY(char, topicStr, sizeof(char) * topic.length +1);
    memcpy(topicStr, topic.data, topic.length);
    topicStr[topic.length] = '\0';

    enum MQTTErrors mqttErr = mqtt_subscribe(client, topicStr, (UA_Byte) qos);
    if(mqttErr != MQTT_OK){
        const char* errorStr = mqtt_error_str(mqttErr);
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: subscribe: %s", errorStr);
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
unSubscribeMqtt(UA_PubSubChannelDataMQTT* channelData, UA_String topic){
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

UA_StatusCode
yieldMqtt(UA_PubSubChannelDataMQTT* channelData, UA_UInt16 timeout) {
    if(channelData == NULL || timeout == 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_Socket *socket = channelData->socket;
    if(socket == NULL) {
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    if(socket->socketState != UA_SOCKETSTATE_OPEN) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK,
                     "PubSub MQTT: yield: Tcp Connection not established!");
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    struct mqtt_client *client = (struct mqtt_client *)channelData->mqttClient;
    client->socketfd->timeout = timeout;

    enum MQTTErrors error = mqtt_sync(client);
    if(error == MQTT_OK) {
        return UA_STATUSCODE_GOOD;
    } else if(error == -1) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK, "PubSub MQTT: yield: Communication Error.");
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }
    
    /* map mqtt errors to ua errors */
    const char* errorStr = mqtt_error_str(error);
    UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: yield: error: %s", errorStr);
    
    switch(error){
        case MQTT_ERROR_CONNECTION_CLOSED:
            return UA_STATUSCODE_BADNOTCONNECTED;
        case MQTT_ERROR_SOCKET_ERROR:
            return UA_STATUSCODE_BADCOMMUNICATIONERROR;
        case MQTT_ERROR_CONNECTION_REFUSED:
            return UA_STATUSCODE_BADCONNECTIONREJECTED;
            
        default:
            return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }
}

UA_StatusCode
publishMqtt(UA_PubSubChannelDataMQTT* channelData, UA_String topic, const UA_ByteString *buf, UA_Byte qos){
    if(channelData == NULL || buf == NULL ){
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_STACKARRAY(char, topicChar, sizeof(char) * topic.length +1);
    memcpy(topicChar, topic.data, topic.length);
    topicChar[topic.length] = '\0';
    
    struct mqtt_client* client = (struct mqtt_client*)channelData->mqttClient;
    if(client == NULL)
        return UA_STATUSCODE_BADNOTCONNECTED;

    /* publish */
    enum MQTTPublishFlags flags;
    if(qos == 0){
        flags = MQTT_PUBLISH_QOS_0;
    }else if( qos == 1){
        flags = MQTT_PUBLISH_QOS_1;
    }else if( qos == 2){
        flags = MQTT_PUBLISH_QOS_2;
    }else{
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_NETWORK, "PubSub MQTT: publish: Bad Qos Level.");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    mqtt_publish(client, topicChar, buf->data, buf->length, (uint8_t)flags);
    if (client->error != MQTT_OK) {
        if(client->error == MQTT_ERROR_SEND_BUFFER_IS_FULL){
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: publish: Send buffer is full. "
                                                               "Possible reasons: send buffer is to small, "
                                                               "sending to fast, broker not responding.");
        }else{
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "PubSub MQTT: publish: %s", mqtt_error_str(client->error));
        }
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }
    return UA_STATUSCODE_GOOD;
}

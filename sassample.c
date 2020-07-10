/**
 * @file sassample.c
 * 
 * @brief Example of an application that uses the Embedded IoT C library. This example avoids using any of the 
 * libraries used by the examples in the below GitHub repository. 
 * 
 * For MQTT it uses MQTT-C https://github.com/LiamBindle/MQTT-C
 * For TLS it used BearSSL: https://bearssl.org
 * 
 * Currently only supports SAS authentication
 * 
 * Application requires at least two and optional three environment variables to be set prior to running:
 *    AZ_IOT_CONNECTION_STRING:               Set to the device's connection string
 *    AZ_IOT_DEVICE_X509_TRUST_PEM_FILE:      Path to the file containing the trusted root certificate in order to validate the server's certificate
 *    AZ_IOT_DEVICE_SAS_TTL:                  Optional time to live in seconds for SAS token - defaults to 3600 seconds
 * 
 * @remark Find information about the Embedded C library at https://github.com/azure//azure-sdk-for-c
 * 
 */

#define VERSION "1.0"

#include <azure/iot/az_iot_hub_client.h>
#include <azure/iot/az_iot_common.h>
#include <azure/core/az_precondition.h>
#include <azure/core/az_span.h>
#include <azure/core/az_platform.h>
#include <azure/core/az_json.h>
#include <azure/core/az_log.h>

#include <azure/core/internal/az_precondition_internal.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>

#include <bearssl.h>
#include <mqtt.h>

#include "azheap.h"
#include "bearssltagenerator.h"
#include "llcomms.h"
#include "base64util.h"

/**
 * Structure used to hold options and other values that are only calculated once
 */ 
typedef struct 
{
    az_span connectionString;
    az_span trustedRootCert;
    az_span hostname;
    az_span port;
    az_span deviceId;
    az_span sharedAccessKey;
    az_span decodedSAK;
    char *client_id;
    char *user_id;
    bearssl_context ctx;
    uint32_t sas_ttl;
} CONFIGURATION;

/**
 * Structure used to pass control blocks to published messages handler along with values that they may modify
 */
typedef struct 
{
    struct mqtt_client *mqttclient;
    az_iot_hub_client *client;
    uint16_t interval;
    bool run;
} PUBLISH_USER;

// Buffer size constants
#define HEAP_LENGTH 1024 * 12
#define MQTT_SENDBUF_LENGTH 1024
#define MQTT_RECVBUF_LENGTH 1024

HEAPHANDLE hHeap = NULL;            /** Global heap pointer */


volatile bool noctrlc = true;       /** Global so signal trap can request graceful termination */

/**
 * @brief Read option value from environment
 * 
 * @param[in] name User friendly name of parameter
 * @param[in] env_name Name of environment variable
 * @param[in] default_value Default value environment variable is not found - can be NULL
 * @param[in] hide_value When true do not log the received value
 * @param[in,out] buffer Value will be stored in this az_span
 * @param[out] out_value Value will be stored in this span and the length set - can be the same variable as above
 * 
 * @returns az_result of AZ_OK if successful
 */ 
static az_result read_configuration_entry(
    const char* name,
    const char* env_name,
    char* default_value,
    bool hide_value,
    az_span buffer,
    az_span* out_value)
{
  printf("%s = ", name);
  char* env = getenv(env_name);

  if (env != NULL)
  {
    printf("%s\n", hide_value ? "***" : env);
    az_span env_span = az_span_from_str(env);
    AZ_RETURN_IF_NOT_ENOUGH_SIZE(buffer, az_span_size(env_span) + 1);
    az_span remainder = az_span_copy(buffer, env_span);
    az_span_copy_u8(remainder, '\0');
    *out_value = az_span_slice(buffer, 0, az_span_size(env_span) + 1);
  }
  else if (default_value != NULL)
  {
    printf("%s\n", default_value);
    az_span default_span = az_span_from_str(default_value);
    AZ_RETURN_IF_NOT_ENOUGH_SIZE(buffer, az_span_size(default_span));
    az_span remainder = az_span_copy(buffer, default_span);
    az_span_copy_u8(remainder, '\0');
    *out_value = az_span_slice(buffer, 0, az_span_size(default_span) + 1);
  }
  else
  {
    printf("(missing) Please set the %s environment variable.\n", env_name);
    return AZ_ERROR_ARG;
  }

  return AZ_OK;
}

/**
 * @brief Populates the configuration variable with the options
 * 
 * @param[in,out] configuration Values will be placed in this structure
 * 
 * @returns az_result of AZ_OK is successful
 */
static az_result read_configuration_and_init_client(CONFIGURATION *configuration)
{
    static const char* ENV_DEVICE_CONNECTION_STRING = "AZ_IOT_CONNECTION_STRING";
    static const char* ENV_DEVICE_X509_TRUST_PEM_FILE = "AZ_IOT_DEVICE_X509_TRUST_PEM_FILE";
    static const char* ENV_DEVICE_SAS_TOKEN_TTL = "AZ_IOT_DEVICE_SAS_TTL";

    _az_PRECONDITION_NOT_NULL(configuration);

    az_span work_span;

    configuration->connectionString = az_heap_alloc(hHeap, 256);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "Connection String", ENV_DEVICE_CONNECTION_STRING, NULL, true, configuration->connectionString, &configuration->connectionString));
    configuration->connectionString = az_heap_adjust(hHeap, configuration->connectionString);

    // Not actually large enough to contain the maximum path but should do
    configuration->trustedRootCert = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Trusted PEM Store File", ENV_DEVICE_X509_TRUST_PEM_FILE, NULL, false, configuration->trustedRootCert, &configuration->trustedRootCert));
    configuration->trustedRootCert = az_heap_adjust(hHeap, configuration->trustedRootCert);

    work_span = az_heap_alloc(hHeap, 10);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "SAS Token Time to Live", ENV_DEVICE_SAS_TOKEN_TTL, "3600", false, work_span, &work_span));

    az_result ar = az_span_atou32(az_span_slice(work_span, 0, az_span_size(work_span) - 1), &configuration->sas_ttl);
    az_heap_free(hHeap, work_span);

    return ar;
}

/**
 * @brief Splits a connection string into its keyword/value components
 * 
 * @param[in,out] configuration Takes the connection string from here and puts the parts back in
 * 
 * @returns az_result of AZ_OK if successful
 */
static az_result split_connection_string(CONFIGURATION *configuration)
{
    static const char *HOSTNAME = "hostname";
    static const char *DEVICEID = "deviceid";
    static const char *SHAREDACCESSKEY = "sharedaccesskey";

    static const char PORT[] = "8883";

    char buffer[256];
    bool inKeyword = true;
    char *walker = az_span_ptr(configuration->connectionString);
    char *out = buffer;
    char *valueStart;
    az_span *configPtr;
    az_span work;

    _az_PRECONDITION_NOT_NULL(configuration);

    configuration->hostname = AZ_SPAN_NULL;
    configuration->port = AZ_SPAN_NULL;
    configuration->deviceId = AZ_SPAN_NULL;
    configuration->sharedAccessKey = AZ_SPAN_NULL;

    while (true)
    {
        if (inKeyword && *walker == '=')
        {
            *out = '\0';
            if (0 == strcmp(HOSTNAME, buffer))
                configPtr = &configuration->hostname;
            else if (0 == strcmp(DEVICEID, buffer))
                configPtr = &configuration->deviceId;
            else if (0 == strcmp(SHAREDACCESSKEY, buffer))
                configPtr = &configuration->sharedAccessKey;
            else
                return AZ_ERROR_ARG;
            
            out = buffer;
            valueStart = ++walker;
            inKeyword = false;
        }
        else if (!inKeyword && (*walker == '\0' || *walker == ';'))
        {
            *configPtr = az_heap_alloc(hHeap, walker - valueStart);
            az_span_copy(*configPtr, az_span_init(buffer, az_span_size(*configPtr)));

            if (*walker)
            {
                out = buffer;
                inKeyword = true;
                walker++;
            }
            else
            {
                break;
            }
        }
        else
        {
            *out++ = inKeyword? tolower(*walker++) : *walker++;
        }
    }

    az_heap_free(hHeap, configuration->connectionString);
    configuration->connectionString = AZ_SPAN_NULL;
    configuration->port = az_span_init((uint8_t *)PORT, strlen(PORT));

    return (az_span_size(configuration->hostname) != 0 && 
        az_span_size(configuration->deviceId) != 0 &&
        az_span_size(configuration->sharedAccessKey) != 0)
    ? AZ_OK
    : AZ_ERROR_ARG;
}

/**
 * @brief Prints a string without a terminating NULL to the console with an
 * optional leader.
 * 
 * @param[in] leader If not NULL will be printed before the array
 * @param[in] buffer Characters to print
 * @param[in] buffer_len Number of characters in \p buffer
 */
static void print_array(const char *leader, const char *buffer, int buffer_len)
{
    if (leader != NULL)
    {
        printf("%s", leader);
    }
    
    if (buffer != NULL && buffer_len > 0)
        fwrite(buffer, 1, buffer_len, stdout);

    putc('\n', stdout);
}

/**
 * @brief A quick and dirty URL decoder. Decoding is done in place. Only works
 * with ASCII.
 * 
 * @param[in,out] in The string to decode. Result will be placed in here too
 */
static void url_decode_in_place(char *in)
{
    char *walker = in;
    char *mover;

    if (in == NULL)
        return;

    while (*walker)
    {
        if (*walker == '%')
        {
            char byte0 = *(walker + 1);
            char byte1 = *(walker + 2);
            char output = 0;

            if (byte0 >= 'a' && byte0 <= 'f')
                byte0 -= '\x20';

            if (byte1 >= 'a' && byte1 <= 'f')
                byte1 -= '\x20';

            if (((byte0 < '0' || byte0 > '9') && (byte0 < 'A' || byte0 > 'F')) ||
                ((byte1 < '0' || byte1 > '9') && (byte1 < 'A' || byte0 > 'F')))
                return;

            output = (byte0 >= '0' && byte0 <= '9')?
                (byte0 - '\x30') << 4:
                (byte0 - '\x37') << 4;
            
            output |= (byte1 >= '0' && byte1 <= '9')?
                (byte1 - '\x30'):
                (byte1 - '\x37');
            
            *walker = output;

            mover = walker + 1;

            while (*(mover + 2))
            {
                *mover = *(mover + 2);
                mover++;
            }

            *mover = '\0';
        }

        ++walker;
    }
}

/**
 * @brief Used to pass CTRL-C to main thread to allow graceful closure
 */
void signalHandler(int signum) {
    (void)signum;       // Will always be SIGINT
    noctrlc = false;
}

/**
 * @brief Called to process interval direct method. Will modify the interval that telemetry is sent at if the payload is valid.
 * Payload should be in the format { "value": N } where N is greater than 0 and less than or equal to 120.
 * 
 * @param[in] publish_user: Passed via the user word. Contains interval value to update
 * @param[in] method_request: Method name and request id
 * @param[in] payload: Data sent by client
 */
static void method_interval(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload)
{
    az_json_parser json_parser;
    bool error = false;
    az_result result;
    az_json_token out_token;
    char workArea[256];
    size_t out_topic_length;
    double out_value;

    result = az_json_parse_by_pointer(payload, AZ_SPAN_FROM_STR("/value"), &out_token);

    if (!az_failed(result) && out_token.kind == AZ_JSON_TOKEN_NUMBER && !az_failed(az_json_token_get_number(&out_token, &out_value)))
    {
        int work = round(out_value);

        if (work < 1 || work > 120)
        {
            printf("New interval of %d is out of range\n", work);
            error = true;
        }
        else
        {
            publish_user->interval = work;
            printf("Interval modifed to %d\n", publish_user->interval);
        }
    }
    else
    {
        printf("Invalid JSON\n");
        error = true;
    }
    
    if (!error)
    {
        if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
            publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, workArea, sizeof(workArea), &out_topic_length)))
        {
            char response[] = "{ \"response\": \"success\" }";
            if (MQTT_OK != mqtt_publish(publish_user->mqttclient, workArea, response, strlen(response), 0))
            {
                printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqttclient->error));
            }
        }
    }
    else
    {
        if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
            publish_user->client, method_request->request_id, AZ_IOT_STATUS_BAD_REQUEST, workArea, sizeof(workArea), &out_topic_length)))
        {
            char response[] = "{ \"response\": \"error\", \"message\": \"Interval is out of range\" }";
            if (MQTT_OK != mqtt_publish(publish_user->mqttclient, workArea, response, strlen(response), 0))
            {
                printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqttclient->error));
            }
        }
    }
}

/**
 * @brief Called to process kill direct method. Ends the program
 * 
 * @param[in] publish_user: Passed via the user word. Contains terminate flag
 * @param[in] method_request: Method name and request id
 * @param[in] payload: Data sent by client (ignored)
 */
static void method_kill(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload)
{
    // payload should be null as in {} - not going to bother checking it
    char workArea[256];
    size_t out_topic_length;

    publish_user->run = false;

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, workArea, sizeof(workArea), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"success\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqttclient, workArea, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqttclient->error));
        }
    }
}

/**
 * @brief Called to process test direct method. Just prints the payload
 * 
 * @param[in] publish_user: Passed via the user word (ignored)
 * @param[in] method_request: Method name and request id
 * @param[in] payload: Data sent by client - just prints this
 */
static void method_test(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload)
{
    char workArea[256];
    size_t out_topic_length;

    printf("%s\n", az_span_ptr(payload));

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, workArea, sizeof(workArea), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"success\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqttclient, workArea, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqttclient->error));
        }
    }
}

/**
 * @brief Called to process an unrecognized command - returns an error to the hub.
 * 
 * @param[in] publish_user: Passed via the user word
 * @param[in] method_request: Method name and request id
 * @param[in] payload: Data sent by client
 */
static void method_unknown(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload)
{
    char workArea[256];
    size_t out_topic_length;

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_BAD_REQUEST, workArea, sizeof(workArea), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"error\", \"message\": \"no such method\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqttclient, workArea, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqttclient->error));
        }
    }
}

/**
 * @brief This function is called whenever a message is publish on any of the subscribed topics. It will figure out if this is a
 * C2D message or a direct method. The former just prints the message whereas the latter will call the appropriate function if the
 * command is recognized or the unknown to return an error.
 * 
 * @param[in] publish_user: Address of user word passed. Contains interval value to update
 * @param[in] method_request: Method name and request id
 * @param[in] payload: Data sent by client
 */
static void publish_callback(void** state, struct mqtt_response_publish *published) 
{
    PUBLISH_USER *publish_user = (PUBLISH_USER *)(*state);

    char workArea[256];

    az_span in_topic = az_span_init((uint8_t*)published->topic_name, published->topic_name_size);
    az_iot_hub_client_c2d_request c2d_request;
    az_iot_hub_client_method_request method_request;
    az_pair out;

    /* AZ_ERROR_IOT_TOPIC_NO_MATCH */
    if (AZ_OK == az_iot_hub_client_c2d_parse_received_topic(publish_user->client, in_topic, &c2d_request))
    {
        printf("Received C2D message:\n");
        out = AZ_PAIR_NULL;

        while (AZ_OK == az_iot_hub_client_properties_next(&c2d_request.properties, &out))
        {
            if (az_span_size(out.key) < sizeof(workArea) && az_span_size(out.value) < sizeof(workArea))
            {
                az_span_to_str(workArea, sizeof(workArea), out.key);
                url_decode_in_place(workArea);
                printf("key=%s; ", workArea);
                az_span_to_str(workArea, sizeof(workArea), out.value);
                url_decode_in_place(workArea);
                printf("value=%s\n", workArea);
            }
            else 
            {
                print_array("Property too long to process - key: ", az_span_ptr(out.key), az_span_size(out.key));
                print_array("                             value: ", az_span_ptr(out.value), az_span_size(out.value));
            }
        }
    }
    else if (AZ_OK == az_iot_hub_client_methods_parse_received_topic(publish_user->client, in_topic, &method_request))
    {
        if (az_span_size(method_request.name) < sizeof(workArea))
        {
            size_t out_topic_length;

            az_span_to_str(workArea, sizeof(workArea), method_request.name);

            printf("Received direct method to invoke %s\n", workArea);

            az_span payload = az_span_init((uint8_t *)published->application_message, published->application_message_size);

            if (strcmp(workArea, "test") == 0)
            {
                method_test(publish_user, &method_request, payload);
            }
            else if (strcmp(workArea, "kill") == 0)
            {
                method_kill(publish_user, &method_request, payload);
            }
            else if (strcmp(workArea, "interval") == 0)
            {
                method_interval(publish_user, &method_request, payload);
            }
            else
            {
                method_unknown(publish_user, &method_request, payload);
            }
        }
        else
        {
            printf("Failed to parse method name\n");
        }
    }
    else
    {
        if (az_span_size(in_topic) < sizeof(workArea))
        {
            az_span_to_str(workArea, sizeof(workArea), in_topic);
            printf("Unable to parse topic %s\n", workArea);
        }
        else
        {
            print_array("No clue what is going on with this message: ", published->topic_name, published->topic_name_size);
        }
    }
}

/**
 * @brief Generates the SAS key to connect to the IoT hub
 * 
 * @param[in] client: The IoT client data block
 * @param[in] decodedSAK: Shared access key decoded from Base64
 * @param[in] expiryTime: Number of seconds for SAS token TTL - must be greater than 50
 * @param[out] mqtt_password: Buffer for password
 * @param[in] mqtt_password_length: Length of password buffer
 * @param[out] mqtt_password_out_length: Length of returned password
 *
 * @returns AZ_OK if successful
 */
static az_result getPassword(az_iot_hub_client *client, 
        az_span decodedSAK, 
        long expiryTime, 
        char *mqtt_password, 
        size_t mqtt_password_length,
        size_t *mqtt_password_out_length)
{
    az_result rc;
    br_sha256_context sha256_context;
    br_hmac_key_context hmac_key_context;
    br_hmac_context hmac_context;
    uint8_t hashedData_buffer[32];
    uint8_t encoded_data_buffer[(sizeof(hashedData_buffer) + 3) * 4 / 3];
    uint8_t signature_buffer[300];
    az_span signature_span = AZ_SPAN_FROM_BUFFER(signature_buffer);
    az_span hashedData_span = AZ_SPAN_FROM_BUFFER(hashedData_buffer);
    az_span encoded_data_span = AZ_SPAN_FROM_BUFFER(encoded_data_buffer);

    _az_PRECONDITION_NOT_NULL(mqtt_password);
    _az_PRECONDITION_NOT_NULL(mqtt_password_out_length);
    _az_PRECONDITION_RANGE(50, mqtt_password_length, UINT32_MAX);

    rc = AZ_OK;

    if (AZ_OK != (rc = az_iot_hub_client_sas_get_signature(client, expiryTime, signature_span, &signature_span)))
    {
        printf("Failed to get string to sign for password - %d\n", rc);
        return rc;
    }

    br_sha256_init(&sha256_context);
    br_hmac_key_init(&hmac_key_context, sha256_context.vtable, az_span_ptr(decodedSAK), az_span_size(decodedSAK));
    br_hmac_init(&hmac_context, &hmac_key_context, 0);
    br_hmac_update(&hmac_context, az_span_ptr(signature_span), az_span_size(signature_span));
    br_hmac_out(&hmac_context, az_span_ptr(hashedData_span));

    if (AZ_OK != (rc = az_encode_base64(hashedData_span, encoded_data_span, &encoded_data_span)))
    {
        printf("Failed to Base64 encode the hash key: %d\n", rc);
    }
    else if (AZ_OK != (rc = az_iot_hub_client_sas_get_password(client, 
            encoded_data_span, 
            expiryTime, 
            AZ_SPAN_NULL, 
            mqtt_password, 
            mqtt_password_length, 
            mqtt_password_out_length)))
    {
        printf("Failed to generate password string: %d\n", rc);
    }

    return rc;
}

/**
 * @brief Subscribes to IoT hub topics for C2D and direct methods
 * 
 * @param[in] mqttclient: The MQTT client data block
 * 
 * @returns MQTTErrors: Any error that occured during subscribe or MQTT_OK
 */
static enum MQTTErrors topic_subscribe(struct mqtt_client *mqttclient)
{
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, 0);
    mqtt_sync(mqttclient);

    return mqttclient->error;
}

/**
 * @brief Connect to the server and start the MQTT session
 * 
 * @param[in] config: Control block with preacquired unchanging values
 * @param[in] client: azure iot hub client
 * @param[in] mqtt_client: MQTT client control block
 * @param[in] reconnect: When true will close MQTT and disconnect the socket first
 * @param[out] expiryTime: Returns the moment that the generated SAS key will expire
 * 
 * @returns 0 = success, -1 = socket failure, -2 = MQTT failure
 */ 
static int server_connect(CONFIGURATION *config, az_iot_hub_client *client, struct mqtt_client *mqtt_client, bool reconnect, long *expiryTime)
{
    int64_t start;
    int attempt = 0;
    int rc = -1;

    if (reconnect)
    {
        printf("Disconnected\n");
        mqtt_disconnect(mqtt_client);
        mqtt_sync(mqtt_client);
        close_socket(&config->ctx);
    }

    while (rc != 0)
    {
        start = az_platform_clock_msec();
        printf("Connection attempt %d\n", attempt + 1);

        if (0 != (rc = open_nb_socket(&config->ctx, az_span_ptr(config->hostname), az_span_ptr(config->port))))
        {
            if (rc == -1)
            {
                az_platform_sleep_msec(az_iot_retry_calc_delay((int)(az_platform_clock_msec() - start), ++attempt, 1000, 20 * 60 * 1000, (rand() % 5000)));
            }
            else
            {
                // Unrecoverable error
                printf("Unable to open socket: Unrecoverable error\n");
                return -1;
            }
        }
    }

    // Get the MQTT password
    *expiryTime = time(NULL) + config->sas_ttl;
    size_t mqtt_password_length = 256;
    char mqtt_password[256];

    if (AZ_OK != (rc = getPassword(client, config->decodedSAK, *expiryTime, mqtt_password, mqtt_password_length, &mqtt_password_length)))
    {
        printf("Failed to generate MQTT password: %d\n", rc);
        return -1;
    }

    // Code just assumes MQTT connect will be ok if socker it connected - failure is considered terminal
    mqtt_connect(mqtt_client, config->client_id, NULL, NULL, 0, config->user_id, mqtt_password, 0, 400);
    topic_subscribe(mqtt_client);
    mqtt_sync(mqtt_client);

    if (mqtt_client->error != MQTT_OK)
    {
        printf("Failed to connect to MQTT broker: %s\n", mqtt_error_str(mqtt_client->error));
    }

    return mqtt_client->error == MQTT_OK? 0 : -2;
}

/**
 * @brief Called when precondition fails. Prints a message and crashes the program;
 */
void precondition_failure_callback()
{
    printf("Precondition failed\n");

    int x = 1;
    int y = 0;
    int z = x / y;
}

/**
 * @brief Print out SDK log data
 * 
 * @param classification[in]: Severity of the message
 * @param message[in]: The message content
 */
void log_func(az_log_classification classification, az_span message)
{
   printf("%.*s\n", az_span_size(message), az_span_ptr(message));
}

/**
 * @brief Entry point of Azure SDK for C sample - sends a message at a fixed interval to an IoT hub
 */
int main()
{
    printf("Azure SDK for C IoT device sample using SAS authentication: V%s\n\n", VERSION);
    // All memory required is defined here
    static uint8_t heap[HEAP_LENGTH];                       // Block of memory used by private heap functions
    static uint8_t bearssl_iobuf[BR_SSL_BUFSIZE_BIDI];      // Buffer for TLS library
    static uint8_t mqtt_sendbuf[2048];                      // Send buffer for MQTT library
    static uint8_t mqtt_recvbuf[1024];                      // Receive buffer for MQTT library

    CONFIGURATION config;
    int rc;

    // Initialize private heap
    hHeap = heapInit(heap, HEAP_LENGTH);

    // Read the configuration from the environment
    if (az_failed(rc = read_configuration_and_init_client(&config)))
    {
        printf("Failed to read configuration variables - %d\n", rc);
        return rc;
    }

    // Convert the certificate into something BearSSL understands
    if (0 == (config.ctx.ta_count = get_trusted_anchors(az_span_ptr(config.trustedRootCert), &config.ctx.anchOut)))
    {
        printf("Trusted root certificate file is invalid\n");
        return 4;
    }

    // Parse the connection string
    if (az_failed(rc = split_connection_string(&config)))
    {
        printf("Failed to parse connection string - make sure it is a device connection string - %d\n", rc);
        return rc;
    }

    az_iot_hub_client client;
    az_iot_hub_client_options options = az_iot_hub_client_options_default();

    // Initialize the embedded IoT data block
    if (AZ_OK != (rc = az_iot_hub_client_init(&client, config.hostname, config.deviceId, &options)))
    {
        printf("Failed to initialize client - %d\n", rc);
        return rc;
    }

    size_t outLength;

    // Get the MQTT client id
    outLength = 200;
    config.client_id = heapMalloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_get_client_id(&client, config.client_id, outLength, &outLength)))
    { 
        printf("Failed to acquire MQTT client id - %d\n", rc);
        return rc;
    }

    config.client_id = heapRealloc(hHeap, config.client_id, outLength + 1);

    // Get the MQTT user name
    outLength = 300;
    config.user_id = heapMalloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_get_user_name(&client, config.user_id, outLength, &outLength)))
    { 
        printf("Failed to acquire MQTT user id - %d\n", rc);
        return rc; 
    }

    config.user_id = heapRealloc(hHeap, config.user_id, outLength + 1);

    // Decode the SAS key
    config.decodedSAK = az_heap_alloc(hHeap, 256);

    if (AZ_OK != (rc = az_decode_base64(config.sharedAccessKey, config.decodedSAK, &config.decodedSAK)))
    {
        printf("Failed to decode the shared access key: %d\n", rc);
        return 4;
    }

    config.decodedSAK = az_heap_adjust(hHeap, config.decodedSAK);

    printf("\nMQTT connection details:\n");
    printf("\tClient Id: %s\n", config.client_id);
    printf("\t  User Id: %s\n", config.user_id);

    // Get the MQTT publish topic
    outLength = 100;
    char *mqtt_topic = heapMalloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_telemetry_get_publish_topic(&client, NULL, mqtt_topic, outLength, &outLength)))
    {
        printf("Failed to get MQTT topic: %d\n", rc);
        return rc;
    }

    mqtt_topic = heapRealloc(hHeap, mqtt_topic, outLength + 1);
    printf("\tTopic: %s\n", mqtt_topic);

    // Optionally set up an alternative precondition failure callback
    az_precondition_failed_set_callback(precondition_failure_callback);

    // Optionally set up a logger
    az_log_set_callback(log_func);

    // Initialize the TLS library
    initialize_TLS(&config.ctx, bearssl_iobuf, BR_SSL_BUFSIZE_BIDI);

    // Setup the MQTT client 
    struct mqtt_client mqttclient;

    PUBLISH_USER publish_user = { &mqttclient, &client, 5, true };

    mqtt_init(&mqttclient, &config.ctx, mqtt_sendbuf, MQTT_SENDBUF_LENGTH, mqtt_recvbuf, MQTT_RECVBUF_LENGTH, publish_callback);
    mqttclient.publish_response_callback_state = &publish_user;

    // open the non-blocking TCP socket (connecting to the broker)
    signal(SIGPIPE, SIG_IGN);

    long expiryTime;

    if (0 != (rc = server_connect(&config, &client, &mqttclient, false, &expiryTime)))
    {
        return -4;
    }

    char msg[300];
    int counter = 49;
    int msgNumber = 0;

    signal(SIGINT, signalHandler);

    printf("\nSending telemtry - press CTRL-C to exit\n\n");

    // Start sending data
    while (publish_user.run && noctrlc)
    {
        // Check for SAS token about to expire and refresh
        if (expiryTime - time(NULL) < (config.sas_ttl * 80 / 100))
        {
            // Need to regenerate a SAS token
            printf("Reaunthenticating\n");
            if (0 != (rc = server_connect(&config, &client, &mqttclient, true, &expiryTime)))
            {
                return -4;
            }
        }

        if (++counter % (publish_user.interval * 10) == 0) 
        {
            // Send some telemetry
            counter = 0;
            sprintf(msg, "{ \"message\": %d }", msgNumber++);
            printf("Sending %s\n", msg);
            mqtt_publish(&mqttclient, mqtt_topic, msg, strlen(msg), MQTT_PUBLISH_QOS_0);
        }

        // Push and pull the data
        mqtt_sync(&mqttclient);

        if (mqttclient.error != MQTT_OK)
        {
            if (mqttclient.error == MQTT_ERROR_SOCKET_ERROR)
            {
                printf("Connection failed - retrying\n");

                if (0 != (rc = server_connect(&config, &client, &mqttclient, true, &expiryTime)))
                {
                    return -4;
                }
            }
            else
            {
                printf("Unrecoverable MQTT error: %s\n", mqtt_error_str(mqttclient.error));
            }
        }

        az_platform_sleep_msec(100);
    }

    printf("Cancel requested - exiting\n");

    mqtt_disconnect(&mqttclient);
    mqtt_sync(&mqttclient);
    close_socket(&config.ctx);

    return 0;
}
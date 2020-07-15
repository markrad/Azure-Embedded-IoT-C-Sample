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
 * Implements the following direct methods:
 * test: Does nothing except print the payload
 * kill: Gracefully terminates the application - payload is ignored and can be empty
 * interval: Modifies the telemetry interval - payload should be '{ "value": n }' where n is an inteval between 1 and 120 in seconds
 * 
 * Implements the following device twin properties
 * interval: Modifies the telemetry interval where the value is number of seconds between 1 and 120
 */

#define VERSION "1.1"

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
    az_span trustedRootCert_filename;
    az_span x509Cert_filename;
    az_span x509Key_filename;
    az_span hostname;
    az_span port;
    az_span deviceId;
    az_span sharedAccessKey;
    az_span decodedSAK;
    br_x509_certificate *x509cert;
    int x509cert_count;
    private_key *x509pk;
    char *client_id;
    char *user_id;
    bearssl_context ctx;
    uint32_t sas_ttl;
    bool usingX509;
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
#define HEAP_LENGTH 1024 * 18
#define MQTT_SENDBUF_LENGTH 1024
#define MQTT_RECVBUF_LENGTH 1024

HEAPHANDLE hHeap = NULL;                        /** Global heap pointer */

volatile bool noctrlc = true;                   /** Global so signal trap can request graceful termination */
volatile bool initial_twin_complete = false;    /** Don't start until we've checked the twin for settings */

static az_result read_configuration_entry(
        const char* name,
        const char* env_name,
        char* default_value,
        bool hide_value,
        az_span buffer,
        az_span* out_value);
static az_result read_configuration_and_init_client(CONFIGURATION *configuration);
static az_result split_connection_string(CONFIGURATION *configuration);
static void print_array(const char *leader, const char *buffer, int buffer_len);
static void print_az_span(const char *leader, const az_span buffer);
static void url_decode_in_place(char *in);
static void signalHandler(int signum);
static void method_interval(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload);
static void method_kill(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload);
static void method_test(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload);
static void method_unknown(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload);
static az_result build_reported_properties(PUBLISH_USER *publish_user, az_span *payload_out);
static int send_reported_property(PUBLISH_USER *publish_user, az_span payload_span);
static int report_property(PUBLISH_USER *publish_user);
static az_result update_property(PUBLISH_USER *publish_user, az_span desired_payload);
static void publish_callback(void** state, struct mqtt_response_publish *published);
static int request_twin(az_iot_hub_client *client, struct mqtt_client *mqttClient);
static az_result getPassword(az_iot_hub_client *client, 
        az_span decodedSAK, 
        long expiryTime, 
        char *mqtt_password, 
        size_t mqtt_password_length,
        size_t *mqtt_password_out_length);
static enum MQTTErrors topic_subscribe(struct mqtt_client *mqttclient);
static int server_connect(CONFIGURATION *config, az_iot_hub_client *client, struct mqtt_client *mqtt_client, bool reconnect, long *expiryTime);
static void precondition_failure_callback();
static void log_func(az_log_classification classification, az_span message);
static void print_heap_info();

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
    static const char* ENV_DEVICE_X509_CLIENT_PEM_FILE = "AZ_IOT_DEVICE_X509_CLIENT_PEM_FILE";
    static const char* ENV_DEVICE_X509_CLIENT_KEY_FILE = "AZ_IOT_DEVICE_X509_CLIENT_KEY_FILE";

    _az_PRECONDITION_NOT_NULL(configuration);

    az_span work_span;

    configuration->connectionString = az_heap_alloc(hHeap, 256);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "Connection String", ENV_DEVICE_CONNECTION_STRING, NULL, true, configuration->connectionString, &configuration->connectionString));
    configuration->connectionString = az_heap_adjust(hHeap, configuration->connectionString);

    // Not actually large enough to contain the maximum path but should do
    configuration->trustedRootCert_filename = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Trusted PEM Store File", ENV_DEVICE_X509_TRUST_PEM_FILE, NULL, false, configuration->trustedRootCert_filename, &configuration->trustedRootCert_filename));
    configuration->trustedRootCert_filename = az_heap_adjust(hHeap, configuration->trustedRootCert_filename);

    work_span = az_heap_alloc(hHeap, 10);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "SAS Token Time to Live", ENV_DEVICE_SAS_TOKEN_TTL, "3600", false, work_span, &work_span));

    configuration->x509Cert_filename = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Client Certificate File", ENV_DEVICE_X509_CLIENT_PEM_FILE, "", false, configuration->x509Cert_filename, &configuration->x509Cert_filename));
    configuration->x509Cert_filename = az_heap_adjust(hHeap, configuration->x509Cert_filename);

    configuration->x509Key_filename = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Client Key File", ENV_DEVICE_X509_CLIENT_KEY_FILE, "", false, configuration->x509Key_filename, &configuration->x509Key_filename));
    configuration->x509Key_filename = az_heap_adjust(hHeap, configuration->x509Key_filename);

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
 * 
 * @note az_span variables have a null terminator but the length does not include that byte
 */
static az_result split_connection_string(CONFIGURATION *configuration)
{
    const char *HOSTNAME = "hostname";
    const char *DEVICEID = "deviceid";
    const char *SHAREDACCESSKEY = "sharedaccesskey";
    const char *X509 = "x509";

    static const char PORT[] = "8883";

    char buffer[256];
    bool inKeyword = true;
    char *walker = az_span_ptr(configuration->connectionString);
    char *out = buffer;
    char *valueStart;
    az_span *configPtr;
    az_span work;
    az_span x509_value = AZ_SPAN_NULL;
    bool x509;

    _az_PRECONDITION_NOT_NULL(configuration);

    configuration->hostname = AZ_SPAN_NULL;
    configuration->port = AZ_SPAN_NULL;
    configuration->deviceId = AZ_SPAN_NULL;
    configuration->sharedAccessKey = AZ_SPAN_NULL;
    configuration->usingX509 = false;

    while (true)
    {
        if (inKeyword && *walker == '=')
        {
            *out = '\0';
            x509 = false;
            if (0 == strcmp(HOSTNAME, buffer))
            {
                configPtr = &configuration->hostname;
            }
            else if (0 == strcmp(DEVICEID, buffer))
            {
                configPtr = &configuration->deviceId;
            }
            else if (0 == strcmp(SHAREDACCESSKEY, buffer))
            {
                configPtr = &configuration->sharedAccessKey;
            }
            else if (0 == strcmp(X509, buffer))
            {
                configPtr = &x509_value;
                x509 = true;
            }
            else
            {
                return AZ_ERROR_ARG;
            }
            
            out = buffer;
            valueStart = ++walker;
            inKeyword = false;
        }
        else if (!inKeyword && (*walker == '\0' || *walker == ';'))
        {
            *configPtr = az_heap_alloc(hHeap, walker - valueStart + 1);
            az_span remainder = az_span_copy(*configPtr, az_span_init(buffer, walker - valueStart));
            az_span_copy_u8(remainder, '\0');
            *configPtr = az_span_slice(*configPtr, 0, walker - valueStart);

            if (x509)
            {
                if (0 == strcmp(az_span_ptr(*configPtr), "true"))
                {
                    configuration->usingX509 = true;
                }
                az_heap_free(hHeap, *configPtr);
            }

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

    // The connection string will never be used again
    az_heap_free(hHeap, configuration->connectionString);
    configuration->connectionString = AZ_SPAN_NULL;
    configuration->port = az_span_init((uint8_t *)PORT, strlen(PORT));

    return (az_span_size(configuration->hostname) != 0 && 
        az_span_size(configuration->deviceId) != 0 &&
        ((az_span_size(configuration->sharedAccessKey) != 0 && configuration->usingX509 == false) ||
         (az_span_size(configuration->sharedAccessKey) == 0 && configuration->usingX509 == true)))
    ? AZ_OK
    : AZ_ERROR_ARG;
}

/**
 * @brief Prints a string without a terminating NULL to the console with an
 * optional leader. New line will be appended.
 * 
 * @param leader[in] If not NULL will be printed before the array
 * @param buffer[in] Characters to print
 * @param buffer_len[in] Number of characters in \p buffer
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
 * @brief Prints an az_span without a terminating NULL to the console with an
 * optional leader. New line will be appended.
 * 
 * @param leader[in] If not NULL will be printed before the array
 * @param buffer[in] az_span to print
 */
static void print_az_span(const char *leader, const az_span buffer)
{
    print_array(leader, az_span_ptr(buffer), az_span_size(buffer));
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
static void signalHandler(int signum)
{
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
            report_property(publish_user);
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
 * @param publish_user[in]: Passed via the user word
 * @param method_request[in]: Method name and request id
 * @param payload[in]: Data sent by client
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
 * @brief Builds the JSON update string for the new interval value.
 * 
 * @param publish_user[in]: Control block
 * @param payload_out[in,out] Span must be initialized and JSON will be placed in its buffer
 * 
 * @return AZ_OK if successful
 */
static az_result build_reported_properties(PUBLISH_USER *publish_user, az_span *payload_out)
{
    static az_span reported_property_name = AZ_SPAN_LITERAL_FROM_STR("interval");

    az_json_builder builder;

    AZ_RETURN_IF_FAILED(az_json_builder_init(&builder, *payload_out, NULL));
    AZ_RETURN_IF_FAILED(az_json_builder_append_begin_object(&builder));
    AZ_RETURN_IF_FAILED(az_json_builder_append_property_name(&builder, reported_property_name));
    AZ_RETURN_IF_FAILED(az_json_builder_append_int32_number(&builder, publish_user->interval));
    AZ_RETURN_IF_FAILED(az_json_builder_append_end_object(&builder));

    *payload_out = az_json_builder_get_json(&builder);

    return AZ_OK;
}

/**
 * @brief Sends the updated property value to update the device twin at the server.
 * 
 * @param publish_user[in]: Control block
 * @param payload_span[in]: JSON to send to the server
 * 
 * @returns Zero if successful
 */
static int send_reported_property(PUBLISH_USER *publish_user, az_span payload_span)
{
    static az_span request_id = AZ_SPAN_LITERAL_FROM_STR("reported_prop");
    char report_topic[128];
    
    printf("Sending updated properties: %.*s\n", az_span_size(payload_span), az_span_ptr(payload_span));

    if (az_failed(az_iot_hub_client_twin_patch_get_publish_topic(publish_user->client, request_id, report_topic, sizeof(report_topic), NULL)))
    {
        printf("Failed to acquire report topic\n");
        return -1;
    }

    mqtt_publish(publish_user->mqttclient, report_topic, az_span_ptr(payload_span), az_span_size(payload_span), 0);

    if (publish_user->mqttclient->error != MQTT_OK)
    {
        printf("Failed to publish reported update: %s\n", mqtt_error_str(publish_user->mqttclient->error));
        return -1;
    }

    return 0;
}

/**
 * @brief Builds and sends a device twin property update
 * 
 * @param publish_user[in]: Control block
 * 
 * @returns Zero if successful
 */
static int report_property(PUBLISH_USER *publish_user)
{
    char buffer[256];
    az_span buffer_span = AZ_SPAN_FROM_BUFFER(buffer);

    if (az_failed(build_reported_properties(publish_user, &buffer_span)))
    {
        printf("Failed to build report JSON\n");
        return -1;
    }

    if (0 != send_reported_property(publish_user, buffer_span))
    {
        printf("Failed to send reported property");
        return -1;
    }

    return 0;
}

/**
 * @brief Parses the JSON from the device twin update and applies it to the interval if it is valid
 * 
 * @param publish_user[in]: Control block
 * @param desired_payload[in]: Desired values from server
 * 
 * @returns AZ_OK if successful
 */
static az_result update_property(PUBLISH_USER *publish_user, az_span desired_payload)
{
    static az_span version_name = AZ_SPAN_LITERAL_FROM_STR("$version");
    static az_span reported_property_name = AZ_SPAN_LITERAL_FROM_STR("interval");
    
    az_json_parser parser;
    az_json_token token;
    az_json_token_member token_member;

    AZ_RETURN_IF_FAILED(az_json_parser_init(&parser, desired_payload));
    AZ_RETURN_IF_FAILED(az_json_parser_parse_token(&parser, &token));
    AZ_RETURN_IF_FAILED(az_json_parser_parse_token_member(&parser, &token_member));

    while (!az_span_is_content_equal(token_member.name, version_name))
    {
        if (az_span_is_content_equal(token_member.name, reported_property_name))
        {
            double property_value = 5.0;

            AZ_RETURN_IF_FAILED(az_json_token_get_number(&token_member.token, &property_value));
            publish_user->interval = (uint8_t)property_value;
            printf("Updating %.*s\" to %d\n", az_span_size(reported_property_name), az_span_ptr(reported_property_name), publish_user->interval);
        }

        AZ_RETURN_IF_FAILED(az_json_parser_parse_token_member(&parser, &token_member));
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
    int rc;

    char workArea[256];

    az_span in_topic = az_span_init((uint8_t*)published->topic_name, published->topic_name_size);
    az_iot_hub_client_c2d_request c2d_request;
    az_iot_hub_client_method_request method_request;
    az_iot_hub_client_twin_response twin_response;
    az_pair out;
    az_json_token out_token;
    az_result az_r;
    double out_value;
    int desired_interval;
    int reported_interval;

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
                print_az_span("Property too long to process - key: ", out.key);
                print_az_span("                             value: ", out.value);
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
    else if (AZ_OK == az_iot_hub_client_twin_parse_received_topic(publish_user->client, in_topic, &twin_response))
    {
        switch (twin_response.response_type)
        {
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_GET:
            print_array("Response type get: ", published->application_message, published->application_message_size);
            printf("Response status: %d\n", twin_response.status);
            print_az_span("Request Id: ", twin_response.request_id);

            if (twin_response.status == AZ_IOT_STATUS_OK)
            {
                az_r = az_json_parse_by_pointer(az_span_init((uint8_t *)published->application_message, published->application_message_size), AZ_SPAN_FROM_STR("/desired/interval"), &out_token);

                if (!az_failed(az_r) && out_token.kind == AZ_JSON_TOKEN_NUMBER && !az_failed(az_json_token_get_number(&out_token, &out_value)))
                {
                    int desired_interval = round(out_value);

                    if (desired_interval < 1 || desired_interval > 120)
                    {
                        printf("Desired interval of %d is out of range\n", desired_interval);
                    }
                    else
                    {
                        if (publish_user->interval != desired_interval)
                        {
                            publish_user->interval = desired_interval;
                            report_property(publish_user);
                        }
                    }
                }
                else
                {
                    az_r = az_json_parse_by_pointer(az_span_init((uint8_t *)published->application_message, published->application_message_size), AZ_SPAN_FROM_STR("/reported/interval"), &out_token);

                    if (!az_failed(az_r) && !az_failed(az_json_token_get_number(&out_token, &out_value)))
                    {
                        reported_interval = round(out_value);
                        publish_user->interval = reported_interval;
                    }
                }

                initial_twin_complete = true;
            }

            break;
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_REPORTED_PROPERTIES:
            printf("Twin reported properties response\n");

            if (published->application_message_size == 0)
            {
                printf("Reported properties were updated successfully\n");
            }
            else
            {
                print_array("Reported properties update failed: ", published->application_message, published->application_message_size);
            }
            
            printf("Response status: %d\n", twin_response.status);
            break;
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_DESIRED_PROPERTIES:
            print_array("Response type desired properties: ", published->application_message, published->application_message_size);
            printf("Response status: %d\n", twin_response.status);
            
            if (az_failed(rc = update_property(publish_user, az_span_init((uint8_t *)published->application_message, published->application_message_size))))
            {
                printf("Failed to update property locally, az_result return code %04x\n", rc);
            }
            else
            {
                report_property(publish_user);
            }
            break;
        default:
            printf("Unrecognized device twin response type: %d\n", twin_response.response_type);
            break;
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
 * @brief Requests the twin document from the server
 * 
 * @param client[in] IoT hub client control block
 * @param mqttClient[in] MQTT control block
 * 
 * @return zero if successful
 */
static int request_twin(az_iot_hub_client *client, struct mqtt_client *mqttClient)
{
    int rc;
    static az_span req_id = AZ_SPAN_LITERAL_FROM_STR("get_twin");
    char twin_topic[128];

    printf("Device requesting twin document from service.\n");

    // Get the topic to send a twin GET publish message to service.
    if (az_failed(rc = az_iot_hub_client_twin_document_get_publish_topic(client, req_id, twin_topic, sizeof(twin_topic), NULL)))
    {
        printf("Unable to get twin document publish topic, az_result return code %04x\n", rc);
        return rc;
    }

    // Publish the twin document request. This will trigger the service to send back the twin document
    // for this device. The response is handled in the on_received function.
    mqtt_publish(mqttClient, twin_topic, NULL, 0, 0);
    mqtt_sync(mqttClient);
    mqtt_sync(mqttClient);

    if (mqttClient->error != MQTT_OK)
    {
        printf("Failed to publish twin document request: %s\n", mqtt_error_str(mqttClient->error));
        return mqttClient->error;
    }

    return 0;
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
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC, 0);
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
    char *mqtt_password = heapMalloc(hHeap, 256);

    if (config->usingX509 == false)
    {
        if (AZ_OK != (rc = getPassword(client, config->decodedSAK, *expiryTime, mqtt_password, mqtt_password_length, &mqtt_password_length)))
        {
            printf("Failed to generate MQTT password: %d\n", rc);
            return -1;
        }
    }
    else
    {
        mqtt_password = NULL;
    }
    

    // Code just assumes MQTT connect will be ok if socker it connected - failure is considered terminal
    mqtt_connect(mqtt_client, config->client_id, NULL, NULL, 0, config->user_id, mqtt_password, 0, 400);
    heapFree(hHeap, mqtt_password);
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
static void precondition_failure_callback()
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
static void log_func(az_log_classification classification, az_span message)
{
   printf("%.*s\n", az_span_size(message), az_span_ptr(message));
}

/**
 * @brief Prints the current private heap statistics
 */
static void print_heap_info()
{
    HEAPINFO hi;

    heapGetInfo(hHeap, &hi);

    printf("Free: %d\tUsed: %d\tLargest: %d\n", hi.freeBytes, hi.usedBytes, hi.largestFree);
}

/**
 * @brief Entry point of Azure SDK for C sample - sends a message at a fixed interval to an IoT hub
 */
int main()
{
    printf("Azure SDK for C IoT device sample: V%s\n\n", VERSION);
    // All memory required is defined here
    static uint8_t heap[HEAP_LENGTH];                       // Block of memory used by private heap functions
    static uint8_t bearssl_iobuf[BR_SSL_BUFSIZE_BIDI];      // Buffer for TLS library
    static uint8_t mqtt_sendbuf[2048];                      // Send buffer for MQTT library
    static uint8_t mqtt_recvbuf[1024];                      // Receive buffer for MQTT library

    CONFIGURATION config;
    int rc;

    // Initialize private heap
    hHeap = heapInit(heap, HEAP_LENGTH);

    // Optionally set up an alternative precondition failure callback
    az_precondition_failed_set_callback(precondition_failure_callback);

    // Read the configuration from the environment
    if (az_failed(rc = read_configuration_and_init_client(&config)))
    {
        printf("Failed to read configuration variables - %d\n", rc);
        return rc;
    }

    // Convert the certificate into something BearSSL understands
    if (0 == (config.ctx.ta_count = get_trusted_anchors(az_span_ptr(config.trustedRootCert_filename), &config.ctx.anchOut)))
    {
        printf("Trusted root certificate file is invalid\n");
        return 4;
    }

    az_heap_free(hHeap, config.trustedRootCert_filename);
    config.trustedRootCert_filename = AZ_SPAN_NULL;

    // Parse the connection string
    if (az_failed(rc = split_connection_string(&config)))
    {
        printf("Failed to parse connection string - make sure it is a device connection string - %d\n", rc);
        return rc;
    }

    az_heap_free(hHeap, config.connectionString);
    config.connectionString = AZ_SPAN_NULL;

    if (config.usingX509 == true)
    {
        if (az_span_size(config.x509Cert_filename) == 0 || az_span_size(config.x509Key_filename) == 0)
        {
            printf("Connection specifies X509 authentication but certificate or key was not passed\n");
            return 4;
        }
        else
        {
            if (0 != read_private_key(az_span_ptr(config.x509Key_filename), &config.x509pk))
            {
                printf("Unable to parse private key\n");
                return 4;
            }

            if ((config.x509cert_count = read_certificates_string(az_span_ptr(config.x509Cert_filename), &config.x509cert)) <= 0)
            {
                printf("Unable to parse device certificate\n");
                return 4;
            }

            az_heap_free(hHeap, config.x509Key_filename);
            config.x509Key_filename = AZ_SPAN_NULL;
            az_heap_free(hHeap, config.x509Cert_filename);
            config.x509Cert_filename = AZ_SPAN_NULL;
        }
    }
    else
    {
        config.x509pk = NULL;
    }
    

    az_iot_hub_client client;
    az_iot_hub_client_options options = az_iot_hub_client_options_default();

    // Initialize the embedded IoT data block
    if (AZ_OK != (rc = az_iot_hub_client_init(&client, config.hostname, config.deviceId, &options)))
    {
        printf("Failed to initialize client - %d\n", rc);
        return rc;
    }

    az_heap_free(hHeap, config.deviceId);
    config.deviceId = AZ_SPAN_NULL;

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

    if (config.usingX509 == false)
    {
        // Decode the SAS key
        config.decodedSAK = az_heap_alloc(hHeap, 256);

        if (AZ_OK != (rc = az_decode_base64(config.sharedAccessKey, config.decodedSAK, &config.decodedSAK)))
        {
            printf("Failed to decode the shared access key: %d\n", rc);
            return 4;
        }

        config.decodedSAK = az_heap_adjust(hHeap, config.decodedSAK);
    }
    else
    {
        config.decodedSAK = AZ_SPAN_NULL;
    }
    

    printf("\nMQTT connection details\n");
    printf("\tAuthentication: %s\n", (config.usingX509? "X.509" : "SAS Token"));
    printf("\t     Client Id: %s\n", config.client_id);
    printf("\t       User Id: %s\n", config.user_id);

    // Get the MQTT publish topic
    outLength = 100;
    char *mqtt_topic = heapMalloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_telemetry_get_publish_topic(&client, NULL, mqtt_topic, outLength, &outLength)))
    {
        printf("Failed to get MQTT topic: %d\n", rc);
        return rc;
    }

    mqtt_topic = heapRealloc(hHeap, mqtt_topic, outLength + 1);
    printf("\t         Topic: %s\n", mqtt_topic);

    // Optionally set up a logger
    az_log_set_callback(log_func);

    // Initialize the TLS library
    if (0 != initialize_TLS(&config.ctx, config.x509cert, config.x509cert_count, config.x509pk, bearssl_iobuf, BR_SSL_BUFSIZE_BIDI))
    {
        printf("TLS initialization failed\n");
        return 4;
    }

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

    if (0 != (rc = request_twin(&client, &mqttclient)))
    {
        printf("Failed to request twin: %d\n", rc);
    }

    while (!initial_twin_complete)
    {
        mqtt_sync(&mqttclient);
        az_platform_sleep_msec(100);
    }

    print_heap_info();

    printf("\nSending telemtry at interval %d - press CTRL-C to exit\n\n", publish_user.interval);

    // Start sending data
    while (publish_user.run && noctrlc)
    {
        // Check for SAS token about to expire and refresh
        if (config.usingX509 == false && expiryTime - time(NULL) < (config.sas_ttl * 80 / 100))
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
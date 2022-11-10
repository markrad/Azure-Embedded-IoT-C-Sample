/**
 * @file devicesample.c
 * 
 * @brief Example of an application that uses the Embedded IoT C library. This example avoids using any of the 
 * libraries used by the examples in the below GitHub repository. 
 * 
 * For MQTT it uses MQTT-C https://github.com/LiamBindle/MQTT-C
 * For TLS it used BearSSL: https://bearssl.org
 * 
 * Supports either SAS token or X.509 authentication depending upon the content of the connection string
 * 
 * Application requires various environment variables depending upon if SAS Token or X.509 authenticatin is used
 *    AZ_IOT_CONNECTION_STRING:               Always required. Set to the device's connection string
 *    AZ_IOT_DEVICE_X509_TRUST_PEM_FILE:      Always required. Path to the file containing the trusted root certificate in order to validate the server's certificate
 *    AZ_IOT_DEVICE_SAS_TTL:                  Optional, applicable to SAS authentication only. Time to live in seconds for SAS token - defaults to 3600 seconds
 *    AZ_IOT_DEVICE_X509_CLIENT_PEM_FILE:     Required for X.509 authentication. File name of client's certficate in PEM format
 *    AZ_IOT_DEVICE_X509_CLIENT_KEY_FILE:     Required for X.509 authentication. File name of client's private key in PEM format
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
    az_iot_hub_client *client;
    az_span connection_string;
    az_span trusted_root_cert_filename;
    az_span x509_cert_filename;
    az_span x509Key_filename;
    az_span hostname;
    az_span port;
    az_span device_id;
    az_span shared_access_key;
    az_span decoded_SAK;
    br_x509_certificate *x509_cert;
    long expiry_time;
    int x509_cert_count;
    private_key *x509pk;
    char *client_id;
    char *user_id;
    uint8_t *mqtt_sendbuff;
    uint8_t *mqtt_recvbuff;
    size_t mqtt_sendbuff_length;    
    size_t mqtt_recvbuff_length;
    bearssl_context ctx;
    uint32_t sas_ttl;
    bool using_X509;
    bool connected;
} CONFIGURATION;

/**
 * Structure used to pass control blocks to published messages handler along with values that they may modify
 */
typedef struct 
{
    struct mqtt_client *mqtt_client;
    az_iot_hub_client *client;
    uint16_t interval;
    bool run;
} PUBLISH_USER;

// Buffer size constants
#define HEAP_LENGTH 1024 * 12
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
static void signal_handler(int signum);
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
static az_result get_password(az_iot_hub_client *client, 
        az_span decoded_SAK, 
        long expiryTime, 
        char *mqtt_password, 
        size_t mqtt_password_length,
        size_t *mqtt_password_out_length);
static enum MQTTErrors topic_subscribe(struct mqtt_client *mqtt_client);
static void precondition_failure_callback();
static void log_func(az_log_classification classification, az_span message);
static void print_heap_info();
static az_result json_find_property(az_json_reader *jr, az_span property);
static az_result json_find_path(az_json_reader *jr, az_span path);

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
    az_span env_span = az_span_create_from_str(env);

    if ((az_span_size(buffer) < az_span_size(env)) || (az_span_size(env_span) < 0))
    {
        printf("Buffer too small for %s", env_name);
        return AZ_ERROR_ARG;
    }
    az_span remainder = az_span_copy(buffer, env_span);
    az_span_copy_u8(remainder, '\0');
    *out_value = az_span_slice(buffer, 0, az_span_size(env_span) + 1);
  }
  else if (default_value != NULL)
  {
    printf("%s\n", default_value);
    az_span default_span = az_span_create_from_str(default_value);
    
    if ((az_span_size(buffer) < az_span_size(env)) || (az_span_size(env_span) < 0))
    {
        printf("Buffer too small for %s", env_name);
        return AZ_ERROR_ARG;
    }
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

    configuration->connection_string = az_heap_alloc(hHeap, 256);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "Connection String", ENV_DEVICE_CONNECTION_STRING, NULL, true, configuration->connection_string, &configuration->connection_string));
    configuration->connection_string = az_heap_adjust(hHeap, configuration->connection_string);

    // Not actually large enough to contain the maximum path but should do
    configuration->trusted_root_cert_filename = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Trusted PEM Store File", ENV_DEVICE_X509_TRUST_PEM_FILE, NULL, false, configuration->trusted_root_cert_filename, &configuration->trusted_root_cert_filename));
    configuration->trusted_root_cert_filename = az_heap_adjust(hHeap, configuration->trusted_root_cert_filename);

    work_span = az_heap_alloc(hHeap, 10);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "SAS Token Time to Live", ENV_DEVICE_SAS_TOKEN_TTL, "3600", false, work_span, &work_span));

    configuration->x509_cert_filename = az_heap_alloc(hHeap, 1024);
    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Client Certificate File", ENV_DEVICE_X509_CLIENT_PEM_FILE, "", false, configuration->x509_cert_filename, &configuration->x509_cert_filename));
    configuration->x509_cert_filename = az_heap_adjust(hHeap, configuration->x509_cert_filename);

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
    const char *DEVICE_ID = "deviceid";
    const char *SHARED_ACCESS_KEY = "sharedaccesskey";
    const char *X509 = "x509";

    static const char PORT[] = "8883";

    char buffer[256];
    bool inKeyword = true;
    char *walker = az_span_ptr(configuration->connection_string);
    char *out = buffer;
    char *value_start;
    az_span *config_ptr;
    az_span work;
    az_span x509_value = AZ_SPAN_NULL;
    bool x509;

    _az_PRECONDITION_NOT_NULL(configuration);

    configuration->hostname = AZ_SPAN_NULL;
    configuration->port = AZ_SPAN_NULL;
    configuration->device_id = AZ_SPAN_NULL;
    configuration->shared_access_key = AZ_SPAN_NULL;
    configuration->using_X509 = false;

    while (true)
    {
        if (inKeyword && *walker == '=')
        {
            *out = '\0';
            x509 = false;
            if (0 == strcmp(HOSTNAME, buffer))
            {
                config_ptr = &configuration->hostname;
            }
            else if (0 == strcmp(DEVICE_ID, buffer))
            {
                config_ptr = &configuration->device_id;
            }
            else if (0 == strcmp(SHARED_ACCESS_KEY, buffer))
            {
                config_ptr = &configuration->shared_access_key;
            }
            else if (0 == strcmp(X509, buffer))
            {
                config_ptr = &x509_value;
                x509 = true;
            }
            else
            {
                return AZ_ERROR_ARG;
            }
            
            out = buffer;
            value_start = ++walker;
            inKeyword = false;
        }
        else if (!inKeyword && (*walker == '\0' || *walker == ';'))
        {
            *config_ptr = az_heap_alloc(hHeap, walker - value_start + 1);
            az_span remainder = az_span_copy(*config_ptr, az_span_init(buffer, walker - value_start));
            az_span_copy_u8(remainder, '\0');
            *config_ptr = az_span_slice(*config_ptr, 0, walker - value_start);

            if (x509)
            {
                if (0 == strcmp(az_span_ptr(*config_ptr), "true"))
                {
                    configuration->using_X509 = true;
                }
                az_heap_free(hHeap, *config_ptr);
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
    az_heap_free(hHeap, configuration->connection_string);
    configuration->connection_string = AZ_SPAN_NULL;
    configuration->port = az_span_init((uint8_t *)PORT, strlen(PORT));

    return (az_span_size(configuration->hostname) != 0 && 
        az_span_size(configuration->device_id) != 0 &&
        ((az_span_size(configuration->shared_access_key) != 0 && configuration->using_X509 == false) ||
         (az_span_size(configuration->shared_access_key) == 0 && configuration->using_X509 == true)))
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
 * @brief Finds a property at the same level in the heirarchy as the starting pointer
 * 
 * @param jr [in,out]: Starting location in JSON on input, points to the property's value on output
 * @param property [in]: Property to search for
 * 
 * @returns AZ_OK if found otherwise an error
 */
az_result json_find_property(az_json_reader *jr, az_span property)
{
    az_result result;
    char property_name[32];
    int32_t property_name_length;

    if (az_span_ptr(property) == NULL || az_span_size(property) == 0 || jr == NULL)
    {
        return AZ_ERROR_ARG;
    }

    AZ_RETURN_IF_FAILED(az_json_reader_next_token(jr));

    while (jr->token.kind != AZ_JSON_TOKEN_END_OBJECT)
    {
        if (jr->token.kind == AZ_JSON_TOKEN_PROPERTY_NAME)
        {
            AZ_RETURN_IF_FAILED(az_json_token_get_string(&jr->token, property_name, sizeof(property_name), &property_name_length));
            property_name[property_name_length] = '\0';

            if (az_json_token_is_text_equal(&jr->token, property))
            {
                AZ_RETURN_IF_FAILED(az_json_reader_next_token(jr));
                return AZ_OK;
            }
            else
            {
                AZ_RETURN_IF_FAILED(az_json_reader_skip_children(jr));
            }
        }

        AZ_RETURN_IF_FAILED(az_json_reader_next_token(jr));
    }

    return AZ_ERROR_EOF;
}

/**
 * @brief Searches JSON for a specific property
 * 
 * @param jr [in, out]: az_json_reader containing starting place and returns pointing to property's value
 * @param path [in]: path to search in the format of leve1/level2/target
 * 
 * @returns AZ_OK or error value
 */
az_result json_find_path(az_json_reader *jr, az_span path)
{
    if (az_span_ptr(path) == NULL || az_span_size(path) == 0 || jr == NULL)
    {
        return AZ_ERROR_ARG;
    }

    uint8_t *walk = az_span_ptr(path);
    uint8_t *start = az_span_ptr(path);

    while (az_span_size(path) + 1 != walk - az_span_ptr(path) )
    {
        if (*walk == '/' || az_span_size(path) == walk - az_span_ptr(path))
        {
            if (walk - start == 0)
            {
                return AZ_ERROR_ARG;
            }

            AZ_RETURN_IF_FAILED(json_find_property(jr, az_span_init(start, walk - start)));

            if (az_span_size(path) != walk - az_span_ptr(path) && jr->token.kind != AZ_JSON_TOKEN_BEGIN_OBJECT)
            {
                return AZ_ERROR_ITEM_NOT_FOUND;
            }

            start = walk + 1;
        }

        walk++;
    }

    return AZ_OK;
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
static void signal_handler(int signum)
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
    az_json_reader jr;
    bool error = true;
    char work_area[80];
    char response[128];
    char publish_topic[256];
    size_t out_topic_length;
    uint32_t out_value;
    az_span desired_property_name = AZ_SPAN_LITERAL_FROM_STR("value");

    if (az_failed(az_json_reader_init(&jr, payload, NULL)))
    {
        strcpy(work_area, "Invalid JSON");
        error = true;
    }
    else
    {
        if (az_failed(json_find_property(&jr, desired_property_name)))
        {
            strcpy(work_area, "Property value not found");
            error = true;
        }
        else
        {
            if (az_failed(az_json_token_get_uint32(&jr.token, &out_value)) || out_value < 1 || out_value > 120)
            {
                strcpy(work_area, "Property value is invalid or out of range");
                error = true;
            }
            else 
            {
                publish_user->interval = out_value;
                printf("Interval modifed to %d\n", publish_user->interval);
                report_property(publish_user);
                error = false;
            }
        }
    }
        
    if (!error)
    {
        if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
            publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, publish_topic, sizeof(publish_topic), &out_topic_length)))
        {
            strcpy(response, "{ \"response\": \"success\" }");

            if (MQTT_OK != mqtt_publish(publish_user->mqtt_client, publish_topic, response, strlen(response), 0))
            {
                printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
            }
        }
    }
    else
    {
        if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
            publish_user->client, method_request->request_id, AZ_IOT_STATUS_BAD_REQUEST, publish_topic, sizeof(publish_topic), &out_topic_length)))
        {
            printf("%s\n", work_area);
            sprintf(response, "{ \"response\": \"error\", \"message\": \"%s\" }", work_area);

            if (MQTT_OK != mqtt_publish(publish_user->mqtt_client, publish_topic, response, strlen(response), 0))
            {
                printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
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
    char work_area[256];
    size_t out_topic_length;

    publish_user->run = false;

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, work_area, sizeof(work_area), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"success\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqtt_client, work_area, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
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
    char work_area[256];
    size_t out_topic_length;

    printf("%s\n", az_span_ptr(payload));

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_OK, work_area, sizeof(work_area), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"success\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqtt_client, work_area, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
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
    char work_area[256];
    size_t out_topic_length;

    if (!az_failed(az_iot_hub_client_methods_response_get_publish_topic(
        publish_user->client, method_request->request_id, AZ_IOT_STATUS_BAD_REQUEST, work_area, sizeof(work_area), &out_topic_length)))
    {
        char response[] = "{ \"response\": \"error\", \"message\": \"no such method\" }";
        if (MQTT_OK != mqtt_publish(publish_user->mqtt_client, work_area, response, strlen(response), 0))
        {
            printf("Failed to respond to method: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
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

    az_json_writer builder;

    AZ_RETURN_IF_FAILED(az_json_writer_init(&builder, *payload_out, NULL));
    AZ_RETURN_IF_FAILED(az_json_writer_append_begin_object(&builder));
    AZ_RETURN_IF_FAILED(az_json_writer_append_property_name(&builder, reported_property_name));
    AZ_RETURN_IF_FAILED(az_json_writer_append_int32(&builder, publish_user->interval));
    AZ_RETURN_IF_FAILED(az_json_writer_append_end_object(&builder));

    *payload_out = az_json_writer_get_json(&builder);

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

    mqtt_publish(publish_user->mqtt_client, report_topic, az_span_ptr(payload_span), az_span_size(payload_span), 0);

    if (publish_user->mqtt_client->error != MQTT_OK)
    {
        printf("Failed to publish reported update: %s\n", mqtt_error_str(publish_user->mqtt_client->error));
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
    //static az_span version_name = AZ_SPAN_LITERAL_FROM_STR("$version");
    static az_span reported_property_name = AZ_SPAN_LITERAL_FROM_STR("interval");
    
    az_json_reader jr;
    uint32_t reported_value;

    AZ_RETURN_IF_FAILED(az_json_reader_init(&jr, desired_payload, NULL));
    AZ_RETURN_IF_FAILED(json_find_property(&jr, reported_property_name));
    AZ_RETURN_IF_FAILED(az_json_token_get_uint32(&jr.token, &reported_value));
    publish_user->interval = reported_value;
    printf("Updating %.*s\" to %d\n", az_span_size(reported_property_name), az_span_ptr(reported_property_name), publish_user->interval);
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

    char work_area[256];

    az_span in_topic = az_span_init((uint8_t*)published->topic_name, published->topic_name_size);
    az_iot_hub_client_c2d_request c2d_request;
    az_iot_hub_client_method_request method_request;
    az_iot_hub_client_twin_response twin_response;
    az_pair out;
    az_result az_r;
    uint32_t out_value;
    int desired_interval;
    int reported_interval;

    /* AZ_ERROR_IOT_TOPIC_NO_MATCH */
    if (AZ_OK == az_iot_hub_client_c2d_parse_received_topic(publish_user->client, in_topic, &c2d_request))
    {
        printf("Received C2D message:\n");
        out = AZ_PAIR_NULL;

        while (AZ_OK == az_iot_hub_client_properties_next(&c2d_request.properties, &out))
        {
            if (az_span_size(out.key) < sizeof(work_area) && az_span_size(out.value) < sizeof(work_area))
            {
                az_span_to_str(work_area, sizeof(work_area), out.key);
                url_decode_in_place(work_area);
                printf("key=%s; ", work_area);
                az_span_to_str(work_area, sizeof(work_area), out.value);
                url_decode_in_place(work_area);
                printf("value=%s\n", work_area);
            }
            else 
            {
                print_az_span("Property too long to process - key: ", out.key);
                print_az_span("                             value: ", out.value);
            }
        }
        print_az_span("Message: ", az_span_init((uint8_t *)published->application_message, published->application_message_size));
    }
    else if (AZ_OK == az_iot_hub_client_methods_parse_received_topic(publish_user->client, in_topic, &method_request))
    {
        if (az_span_size(method_request.name) < sizeof(work_area))
        {
            size_t out_topic_length;

            az_span_to_str(work_area, sizeof(work_area), method_request.name);

            printf("Received direct method to invoke %s\n", work_area);

            az_span payload = az_span_init((uint8_t *)published->application_message, published->application_message_size);

            if (strcmp(work_area, "test") == 0)
            {
                method_test(publish_user, &method_request, payload);
            }
            else if (strcmp(work_area, "kill") == 0)
            {
                method_kill(publish_user, &method_request, payload);
            }
            else if (strcmp(work_area, "interval") == 0)
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
                az_json_reader jr;

                if (!az_failed(az_json_reader_init(&jr, az_span_init((uint8_t *)published->application_message, published->application_message_size), NULL)))
                {
                    az_span path = AZ_SPAN_LITERAL_FROM_STR("desired/interval");

                    if (!az_failed(json_find_path(&jr, path)))
                    {
                        if (!az_failed(az_json_token_get_uint32(&jr.token, &out_value) && out_value > 0 && out_value < 120))
                        {
                            publish_user->interval = out_value;
                            report_property(publish_user);
                        }
                        else
                        {
                            printf("Value for interval is either invalid or out of range\n");
                        }
                    }
                    else
                    {
                        if (!az_failed(az_json_reader_init(&jr, az_span_init((uint8_t *)published->application_message, published->application_message_size), NULL)))
                        {
                            az_span path = AZ_SPAN_LITERAL_FROM_STR("reported/interval");

                            if (!az_failed(json_find_path(&jr, path)))
                            {
                                if (!az_failed(az_json_token_get_uint32(&jr.token, &out_value)))
                                {
                                    if (out_value == 0 || out_value > 120)
                                    {
                                        printf("New interval value %d is out of range - set to 120\n", (int)out_value);
                                        out_value = 120;
                                    }
                                    
                                    publish_user->interval = out_value;
                                    report_property(publish_user);
                                }
                                else
                                {
                                    printf("Value for interval is invalid\n");
                                }
                            }
                        }
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
        if (az_span_size(in_topic) < sizeof(work_area))
        {
            az_span_to_str(work_area, sizeof(work_area), in_topic);
            printf("Unable to parse topic %s\n", work_area);
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
 * @param client [in] The IoT client data block
 * @param decoded_SAK [in] Shared access key decoded from Base64
 * @param expiryTime [in] Number of seconds for SAS token TTL - must be greater than 50
 * @param mqtt_password [out] Buffer for password
 * @param mqtt_password_length [in] Length of password buffer
 * @param mqtt_password_out_length [out] Length of returned password
 *
 * @returns  AZ_OK if successful
 */
static az_result get_password(az_iot_hub_client *client, 
        az_span decoded_SAK, 
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
    br_hmac_key_init(&hmac_key_context, sha256_context.vtable, az_span_ptr(decoded_SAK), az_span_size(decoded_SAK));
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
 * @param[in] mqtt_client: The MQTT client data block
 * 
 * @returns MQTTErrors: Any error that occured during subscribe or MQTT_OK
 */
static enum MQTTErrors topic_subscribe(struct mqtt_client *mqtt_client)
{
    mqtt_subscribe(mqtt_client, AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqtt_client, AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqtt_client, AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqtt_client, AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC, 0);
    mqtt_sync(mqtt_client);

    return mqtt_client->error;
}

/**
 * @brief Called by underlying MQTT library when a connection failure is detected
 * 
 * @param mqtt_client [in] MQTT library control block
 * @param reconnect_user [in,out] Address of user data
 */
static void reconnect_callback(struct mqtt_client *mqttClient, void **reconnect_user)
{
    CONFIGURATION *config = *((CONFIGURATION **)reconnect_user);
    int64_t start;
    int attempt = 0;
    int rc = -1;

    if (mqttClient->error != MQTT_ERROR_INITIAL_RECONNECT)
    {
        close_socket(&config->ctx);
        config->connected = false;
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
                return;
            }
        }
    }
    // Get the MQTT password
    size_t mqtt_password_length = 256;
    char *mqtt_password = heap_malloc(hHeap, 256);

    if (config->using_X509 == false)
    {
        config->expiry_time = time(NULL) + config->sas_ttl;

        if (AZ_OK != (rc = get_password(config->client, config->decoded_SAK, config->expiry_time, mqtt_password, mqtt_password_length, &mqtt_password_length)))
        {
            printf("Failed to generate MQTT password: %d\n", rc);
            return;
        }
    }
    else
    {
        config->expiry_time = 0;
        mqtt_password = NULL;
    }

    mqtt_reinit(mqttClient, &config->ctx, config->mqtt_sendbuff, config->mqtt_sendbuff_length, config->mqtt_recvbuff, config->mqtt_recvbuff_length);

    // Code just assumes MQTT connect will be ok if socket connected - failure is considered terminal
    mqtt_connect(mqttClient, config->client_id, NULL, NULL, 0, config->user_id, mqtt_password, 0, 400);
    heap_free(hHeap, mqtt_password);
    topic_subscribe(mqttClient);
    config->connected = true;
    printf("Connected\n");
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
 * @param classification [in] Severity of the message
 * @param message [in] The message content
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

    heap_get_info(hHeap, &hi);

    printf("Free: %d\tUsed: %d\tLargest: %d\n", hi.freeBytes, hi.usedBytes, hi.largestFree);
}

/**
 * @brief Entry point of Azure SDK for C sample - sends a message at a fixed interval to an IoT hub
 */
int main()
{
    printf("Azure SDK for C IoT device sample: V%s\n\n", VERSION);
    // All memory required is defined here (will be allocated in bss on Linux)
    static uint8_t heap[HEAP_LENGTH] __attribute__((aligned));                       // Block of memory used by private heap functions
    static uint8_t bearssl_iobuf[BR_SSL_BUFSIZE_BIDI] __attribute__((aligned));      // Buffer for TLS library
    static uint8_t mqtt_sendbuf[MQTT_SENDBUF_LENGTH] __attribute__((aligned));       // Send buffer for MQTT library
    static uint8_t mqtt_recvbuf[MQTT_RECVBUF_LENGTH] __attribute__((aligned));       // Receive buffer for MQTT library

    CONFIGURATION config;
    int rc;

    // Initialize private heap
    hHeap = heap_init(heap, HEAP_LENGTH);

    // Optionally set up an alternative precondition failure callback
    az_precondition_failed_set_callback(precondition_failure_callback);

    // Read the configuration from the environment
    if (az_failed(rc = read_configuration_and_init_client(&config)))
    {
        printf("Failed to read configuration variables - %d\n", rc);
        return rc;
    }

    // Convert the certificate into something BearSSL understands
    if (0 == (config.ctx.ta_count = get_trusted_anchors(az_span_ptr(config.trusted_root_cert_filename), &config.ctx.anchOut)))
    {
        printf("Trusted root certificate file is invalid\n");
        return 4;
    }

    az_heap_free(hHeap, config.trusted_root_cert_filename);
    config.trusted_root_cert_filename = AZ_SPAN_NULL;

    // Parse the connection string
    if (az_failed(rc = split_connection_string(&config)))
    {
        printf("Failed to parse connection string - make sure it is a device connection string - %d\n", rc);
        return rc;
    }

    az_heap_free(hHeap, config.connection_string);
    config.connection_string = AZ_SPAN_NULL;

    if (config.using_X509 == true)
    {
        if (az_span_size(config.x509_cert_filename) == 0 || az_span_size(config.x509Key_filename) == 0)
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

            if ((config.x509_cert_count = read_certificates_string(az_span_ptr(config.x509_cert_filename), &config.x509_cert)) <= 0)
            {
                printf("Unable to parse device certificate\n");
                return 4;
            }

            az_heap_free(hHeap, config.x509Key_filename);
            config.x509Key_filename = AZ_SPAN_NULL;
            az_heap_free(hHeap, config.x509_cert_filename);
            config.x509_cert_filename = AZ_SPAN_NULL;
        }
    }
    else
    {
        config.x509pk = NULL;
    }

    az_iot_hub_client client;
    az_iot_hub_client_options options = az_iot_hub_client_options_default();

    // Initialize the embedded IoT data block
    if (AZ_OK != (rc = az_iot_hub_client_init(&client, config.hostname, config.device_id, &options)))
    {
        printf("Failed to initialize client - %d\n", rc);
        return rc;
    }

    az_heap_free(hHeap, config.device_id);
    config.device_id = AZ_SPAN_NULL;

    size_t outLength;

    // Get the MQTT client id
    outLength = 200;
    config.client_id = heap_malloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_get_client_id(&client, config.client_id, outLength, &outLength)))
    { 
        printf("Failed to acquire MQTT client id - %d\n", rc);
        return rc;
    }

    config.client_id = heap_realloc(hHeap, config.client_id, outLength + 1);

    // Get the MQTT user name
    outLength = 300;
    config.user_id = heap_malloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_get_user_name(&client, config.user_id, outLength, &outLength)))
    { 
        printf("Failed to acquire MQTT user id - %d\n", rc);
        return rc; 
    }

    config.user_id = heap_realloc(hHeap, config.user_id, outLength + 1);

    if (config.using_X509 == false)
    {
        // Decode the SAS key
        config.decoded_SAK = az_heap_alloc(hHeap, 256);

        if (AZ_OK != (rc = az_decode_base64(config.shared_access_key, config.decoded_SAK, &config.decoded_SAK)))
        {
            printf("Failed to decode the shared access key: %d\n", rc);
            return 4;
        }

        config.decoded_SAK = az_heap_adjust(hHeap, config.decoded_SAK);
    }
    else
    {
        config.decoded_SAK = AZ_SPAN_NULL;
    }
    

    printf("\nMQTT connection details\n");
    printf("\tAuthentication: %s\n", (config.using_X509? "X.509" : "SAS Token"));
    printf("\t     Client Id: %s\n", config.client_id);
    printf("\t       User Id: %s\n", config.user_id);

    // Get the MQTT publish topic
    outLength = 100;
    char *mqtt_topic = heap_malloc(hHeap, outLength);

    if (AZ_OK != (rc = az_iot_hub_client_telemetry_get_publish_topic(&client, NULL, mqtt_topic, outLength, &outLength)))
    {
        printf("Failed to get MQTT topic: %d\n", rc);
        return rc;
    }

    mqtt_topic = heap_realloc(hHeap, mqtt_topic, outLength + 1);
    printf("\t         Topic: %s\n", mqtt_topic);

    // Optionally set up a logger
    az_log_set_callback(log_func);

    // Initialize the TLS library
    if (0 != initialize_TLS(&config.ctx, config.x509_cert, config.x509_cert_count, config.x509pk, bearssl_iobuf, BR_SSL_BUFSIZE_BIDI))
    {
        printf("TLS initialization failed\n");
        return 4;
    }

    config.mqtt_sendbuff = mqtt_sendbuf;
    config.mqtt_sendbuff_length = MQTT_SENDBUF_LENGTH;
    config.mqtt_recvbuff = mqtt_recvbuf;
    config.mqtt_recvbuff_length = MQTT_RECVBUF_LENGTH;
    config.client = &client;

    // Setup the MQTT client 
    struct mqtt_client mqtt_client;

    PUBLISH_USER publish_user = { &mqtt_client, &client, 5, true };

    mqtt_client.publish_response_callback_state = &publish_user;
    mqtt_init_reconnect(&mqtt_client, reconnect_callback, &config, publish_callback);

    // Handle SIGPIPE without interrupt
    signal(SIGPIPE, SIG_IGN);

    // Call sync to force connection
    mqtt_sync(&mqtt_client);

    char msg[300];
    int counter = 49;
    int msgNumber = 0;

    signal(SIGINT, signal_handler);

    if (0 != (rc = request_twin(&client, &mqtt_client)))
    {
        printf("Failed to request twin: %d\n", rc);
    }

    while (!initial_twin_complete)
    {
        mqtt_sync(&mqtt_client);
        az_platform_sleep_msec(100);
    }

    print_heap_info();

    printf("\nSending telemtry at interval %d - press CTRL-C to exit\n\n", publish_user.interval);

    // Start sending data
    while (publish_user.run && noctrlc)
    {
        // Check for SAS token about to expire and refresh
        if (config.connected == true && config.using_X509 == false && config.expiry_time - time(NULL) < (config.sas_ttl * 80 / 100))
        {
            // Need to regenerate a SAS token
            printf("Reaunthenticating\n");
            config.connected = false;
            mqtt_reconnect(&mqtt_client);
        }

        if (mqtt_client.error == MQTT_OK && ++counter % (publish_user.interval * 10) == 0) 
        {
            // Send some telemetry
            counter = 0;
            sprintf(msg, "{ \"message\": %d }", msgNumber++);
            printf("Sending %s\n", msg);
            mqtt_publish(&mqtt_client, mqtt_topic, msg, strlen(msg), MQTT_PUBLISH_QOS_0);
        }

        // Push and pull the data
        mqtt_sync(&mqtt_client);
        az_platform_sleep_msec(100);
    }

    printf("Cancel requested - exiting\n");

    mqtt_disconnect(&mqtt_client);
    mqtt_sync(&mqtt_client);
    close_socket(&config.ctx);

    return 0;
}
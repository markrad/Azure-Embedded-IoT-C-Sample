#include <azure/iot/az_iot_hub_client.h>
#include <azure/iot/az_iot_common.h>
#include <azure/core/az_precondition.h>
#include <azure/core/az_span.h>
#include <azure/core/az_platform.h>
#include <azure/core/az_json.h>

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
    char *trustedRootCert;
    az_span hostname;
    az_span deviceId;
    az_span sharedAccessKey;
    az_span decodedSAK;
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
        "Connection String", ENV_DEVICE_CONNECTION_STRING, NULL, false, configuration->connectionString, &configuration->connectionString));
    configuration->connectionString = az_heap_adjust(hHeap, configuration->connectionString);

    work_span = az_heap_alloc(hHeap, 1024);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "X509 Trusted PEM Store File", ENV_DEVICE_X509_TRUST_PEM_FILE, "", false, work_span, &work_span));
    configuration->trustedRootCert = heapMalloc(hHeap, az_span_size(work_span) + 1);
    az_span_to_str(configuration->trustedRootCert, az_span_size(work_span) + 1, work_span);
    az_heap_free(hHeap, work_span);

    work_span = az_heap_alloc(hHeap, 10);

    AZ_RETURN_IF_FAILED(read_configuration_entry(
        "SAS Token Time to Live", ENV_DEVICE_SAS_TOKEN_TTL, "3600", false, work_span, &work_span));

    work_span = az_span_slice(work_span, 0, az_span_size(work_span) - 1);
    AZ_RETURN_IF_FAILED(az_span_atou32(work_span, &configuration->sas_ttl));
    az_heap_free(hHeap, work_span);

    return AZ_OK;
}

/**
 * @brief Splits a connection string into its keyword/value components
 * 
 * @param[in,out] configuration Takes the connection from here and puts the parts back in
 * 
 * @returns az_result of AZ_OK if successful
 */
static az_result split_connection_string(CONFIGURATION *configuration)
{
    static const char *HOSTNAME = "hostname";
    static const char *DEVICEID = "deviceid";
    static const char *SHAREDACCESSKEY = "sharedaccesskey";

    char buffer[256];
    bool inKeyword = true;
    char *walker = az_span_ptr(configuration->connectionString);
    char *out = buffer;
    char *valueStart;
    az_span *configPtr;
    az_span work;

    _az_PRECONDITION_NOT_NULL(configuration);

    configuration->hostname = AZ_SPAN_NULL;
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
    (void)signum;
    noctrlc = false;
}

static void method_interval(PUBLISH_USER *publish_user, az_iot_hub_client_method_request *method_request, az_span payload)
{
    // payload should contain { "value": N } where N is greater than 0 and not greater than 120
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

    uint8_t hashedData[32];
    uint8_t signature_buffer[300];

    _az_PRECONDITION_NOT_NULL(mqtt_password);
    _az_PRECONDITION_NOT_NULL(mqtt_password_out_length);
    _az_PRECONDITION_RANGE(50, mqtt_password_length, UINT32_MAX);

    rc = AZ_OK;
    az_span signature = az_span_init(signature_buffer, sizeof(signature_buffer));

    if (AZ_OK != (rc = az_iot_hub_client_sas_get_signature(client, expiryTime, signature, &signature)))
    {
        printf("Failed to get string to sign for password - %d\n", rc);
        return rc;
    }

    br_sha256_init(&sha256_context);
    br_hmac_key_init(&hmac_key_context, sha256_context.vtable, az_span_ptr(decodedSAK), az_span_size(decodedSAK));
    br_hmac_init(&hmac_context, &hmac_key_context, 0);
    br_hmac_update(&hmac_context, az_span_ptr(signature), az_span_size(signature));
    br_hmac_out(&hmac_context, hashedData);

    az_span hashedData_span = az_span_init(hashedData, sizeof(hashedData));
    az_span hashedEncoded = az_heap_alloc(hHeap, (sizeof(hashedData) + 3) * 4 / 3);

    if (AZ_OK != (rc = az_encode_base64(hashedData_span, hashedEncoded, &hashedEncoded)))
    {
        printf("Failed to Base64 encode the hash key: %d\n", rc);
    }
    else if (AZ_OK != (rc = az_iot_hub_client_sas_get_password(client, 
            hashedEncoded, 
            expiryTime, 
            AZ_SPAN_NULL, 
            mqtt_password, 
            mqtt_password_length, 
            mqtt_password_out_length)))
    {
        printf("Failed to generate password string: %d\n", rc);
    }

    az_heap_free(hHeap, hashedEncoded);

    return rc;
}

static enum MQTTErrors topic_subscribe(struct mqtt_client *mqttclient)
{
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC, 0);
    mqtt_subscribe(mqttclient, AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, 0);
    mqtt_sync(mqttclient);

    return mqttclient->error;
}

int main()
{
    CONFIGURATION config;
    int rc;
    uint8_t *heap = malloc(HEAP_LENGTH);

    if (heap == NULL)
    {
        printf("Failed to allocate heap\n");
        return 4;
    }

    hHeap = heapInit(heap, HEAP_LENGTH);

    if (az_failed(rc = read_configuration_and_init_client(&config)))
    {
        printf("Failed to read configuration variables - %d\n", rc);
        return rc;
    }

    if (0 == (config.ctx.ta_count = get_trusted_anchors(config.trustedRootCert, &config.ctx.anchOut)))
    {
        printf("Trusted root certificate file is invalid\n");
        return 4;
    }

    if (az_failed(rc = split_connection_string(&config)))
    {
        printf("Failed to parse connection string - make sure it is a device connection string - %d\n", rc);
        return rc;
    }

    az_iot_hub_client client;
    az_iot_hub_client_options options = az_iot_hub_client_options_default();

    if (AZ_OK != (rc = az_iot_hub_client_init(&client, config.hostname, config.deviceId, &options)))
    {
        printf("Failed to initialize client - %d\n", rc);
        return rc;
    }

    size_t outLength;
    char *client_id = heapMalloc(hHeap, 200);

    if (AZ_OK != (rc = az_iot_hub_client_get_client_id(&client, client_id, 200, &outLength)))
    { 
        printf("Failed to acquire MQTT client id - %d\n", rc);
        return rc;
    }

    client_id = heapRealloc(hHeap, client_id, outLength + 1);

    size_t user_id_length = 300;
    char *user_id = heapMalloc(hHeap, user_id_length);

    if (AZ_OK != (rc = az_iot_hub_client_get_user_name(&client, user_id, user_id_length, &user_id_length)))
    { 
        printf("Failed to acquire MQTT user id - %d\n", rc);
        return rc; 
    }

    user_id = heapRealloc(hHeap, user_id, user_id_length + 1);

    long expiryTime = time(NULL) + config.sas_ttl;
    size_t mqtt_password_length = 256;
    char *mqtt_password = heapMalloc(hHeap, mqtt_password_length);

    config.decodedSAK = az_heap_alloc(hHeap, 256);
    if (AZ_OK != (rc = az_decode_base64(config.sharedAccessKey, config.decodedSAK, &config.decodedSAK)))
    {
        printf("Failed to decode the shared access key: %d\n", rc);
        return 4;
    }

    config.decodedSAK = az_heap_adjust(hHeap, config.decodedSAK);

    if (AZ_OK != (rc = getPassword(&client, config.decodedSAK, expiryTime, mqtt_password, mqtt_password_length, &mqtt_password_length)))
    {
        printf("Failed to generate MQTT password: %d\n", rc);
        return 4;
    }

    mqtt_password = heapRealloc(hHeap, mqtt_password, mqtt_password_length + 1);

    printf("\nMQTT connection details:\n");
    printf("\tClient Id: %s\n", client_id);
    printf("\tUser Id: %s\n", user_id);
    printf("\tPassword: %s\n", mqtt_password);

    size_t mqtt_topic_length = 100;
    char *mqtt_topic = heapMalloc(hHeap, mqtt_topic_length);

    if (AZ_OK != (rc = az_iot_hub_client_telemetry_get_publish_topic(&client, NULL, mqtt_topic, mqtt_password_length, &mqtt_topic_length)))
    {
        printf("Failed to get MQTT topic: %d\n", rc);
        return rc;
    }

    mqtt_topic = heapRealloc(hHeap, mqtt_topic, mqtt_topic_length + 1);
    printf("\tTopic: %s\n", mqtt_topic);

    /* open the non-blocking TCP socket (connecting to the broker) */
    
    signal(SIGPIPE, SIG_IGN);

    char *hostname = heapMalloc(hHeap, az_span_size(config.hostname) + 1);

    az_span_to_str(hostname, az_span_size(config.hostname) + 1, config.hostname);

    unsigned char *bearssl_iobuf = malloc(BR_SSL_BUFSIZE_BIDI);

    if (0 != open_nb_socket(&config.ctx, hostname, "8883", bearssl_iobuf, BR_SSL_BUFSIZE_BIDI))
    {
        printf("Unable to open socket\n");
        return 4;
    }

    /* setup a client */
    struct mqtt_client mqttclient;

    uint8_t *mqtt_buffers = malloc(MQTT_SENDBUF_LENGTH + MQTT_RECVBUF_LENGTH);

    PUBLISH_USER publish_user = { &mqttclient, &client, 5, true };

    mqtt_init(&mqttclient, &config.ctx, mqtt_buffers, MQTT_SENDBUF_LENGTH, mqtt_buffers + MQTT_SENDBUF_LENGTH, MQTT_RECVBUF_LENGTH, publish_callback);
    mqttclient.publish_response_callback_state = &publish_user;
    mqtt_connect(&mqttclient, client_id, NULL, NULL, 0, user_id, mqtt_password, 0, 400);
    topic_subscribe(&mqttclient);

    /* check that we don't have any errors */
    if (mqttclient.error != MQTT_OK) {
        printf("error: %s\n", mqtt_error_str(mqttclient.error));
        return -4;
    }

    char msg[300];
    int counter = 49;
    int msgNumber = 0;

    signal(SIGINT, signalHandler);

    printf("\nSending telemtry - press CTRL-C to exit\n\n");

    while (publish_user.run && noctrlc)
    {
        if (expiryTime - time(NULL) < (config.sas_ttl * 80 / 100))
        {
            // Need to regenerate a SAS token
            printf("Reaunthenticating\n");
            mqtt_disconnect(&mqttclient);
            mqtt_sync(&mqttclient);
            close_socket(&config.ctx);
            expiryTime = time(NULL) + config.sas_ttl;
            mqtt_password_length = 256;
            mqtt_password = heapRealloc(hHeap, mqtt_password, mqtt_password_length);

            if (AZ_OK != (rc = getPassword(&client, config.decodedSAK, expiryTime, mqtt_password, mqtt_password_length, &mqtt_password_length)))
            {
                printf("Failed to generate MQTT password: %d\n", rc);
                return 4;
            }

            if (0 != open_nb_socket(&config.ctx, hostname, "8883", bearssl_iobuf, BR_SSL_BUFSIZE_BIDI))
            {
                printf("Unable to open socket\n");
                return 4;
            }

            if (MQTT_OK != mqtt_connect(&mqttclient, client_id, NULL, NULL, 0, user_id, mqtt_password, 0, 400))
            {
                printf("Failed to connect: %s\n", mqtt_error_str(mqttclient.error));
                return 4;
            }

            if (MQTT_OK != topic_subscribe(&mqttclient))
            {
                printf("Failed to connect and subscribe: %s", mqtt_error_str(mqttclient.error));
                return 4;
            }
        }
        if (MQTT_OK != mqtt_sync(&mqttclient) || mqttclient.error != MQTT_OK)
        {
            printf("error: %s\n", mqtt_error_str(mqttclient.error));
            return -4;
        }

        if (++counter % (publish_user.interval * 10) == 0) 
        {
            counter = 0;
            sprintf(msg, "{ \"message\": %d }", msgNumber++);
            printf("Sending %s\n", msg);
            mqtt_publish(&mqttclient, mqtt_topic, msg, strlen(msg), MQTT_PUBLISH_QOS_0);

            if (mqttclient.error != MQTT_OK) {
                printf("error: %s\n", mqtt_error_str(mqttclient.error));
                return -4;
            }
        }

        az_platform_sleep_msec(100);
    }

    printf("Cancel requested - exiting\n");

    mqtt_disconnect(&mqttclient);
    mqtt_sync(&mqttclient);
    close_socket(&config.ctx);

    free(heap);
    free(bearssl_iobuf);
    free(mqtt_buffers);

    return 0;
}
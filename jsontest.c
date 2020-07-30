#include <azure/core/az_json.h>

#include <stdio.h>

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
            printf("Property = %s\n", property_name);

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

int main()
{
    char *test1 = "{ \"value\": 15 }";
    char *test2 =   "{\n"
                    "   \"desired\": {\n"
                    "      \"interval\" : 15\n"
                    "   },\n"
                    "   \"reported\": {\n"
                    "      \"interval\" : 10\n"
                    "   }\n"
                    "}\n";

    printf("test1: \n%s\n", test1);
    printf("test2:\n%s\n", test2);

    az_span az_test1 = az_span_from_str(test1);
    az_span az_test2 = az_span_from_str(test2);

    az_json_reader jr;
    
    if (az_failed(az_json_reader_init(&jr, az_test1, NULL)))
    {
        printf("Failed to initialize reader for test1\n");
        return 4;
    }

    az_span required_property1 = az_span_from_str("value");

    if (az_failed(json_find_property(&jr, required_property1)))
    {
        return 4;
    }

    uint32_t value;

    if (az_failed(az_json_token_get_uint32(&jr.token, &value)))
    {
        printf("Could not get value\n");
        return 4;
    }

    printf("value = %d\n", (int)value);
    
    az_span required_property2 = az_span_from_str("reported");

    if (az_failed(az_json_reader_init(&jr, az_test2, NULL)))
    {
        printf("Failed to initialize reader for test2\n");
        return 4;
    }

    if (az_failed(json_find_property(&jr, required_property2)))
    {
        return 4;
    }

    az_span path = AZ_SPAN_LITERAL_FROM_STR("reported/intervalx");

    if (az_failed(az_json_reader_init(&jr, az_test2, NULL)))
    {
        printf("Failed to initialize reader for test2\n");
        return 4;
    }

    if (az_failed(json_find_path(&jr, path)))
    {
        printf("Failed to find path\n");
        return 4;
    }
 
    if (az_failed(az_json_token_get_uint32(&jr.token, &value)))
    {
        printf("Could not get value\n");
        return 4;
    }

    printf("value = %d\n", (int)value);
    
    return 0;
}
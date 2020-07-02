#include <azure/core/internal/az_precondition_internal.h>

#include "base64util.h"

// Used for Base64 encoding and decoding
static const char* CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

az_result az_decode_base64(az_span source, az_span destination, az_span *out_value)
{
    _az_PRECONDITION_NOT_NULL(out_value);
    _az_PRECONDITION_VALID_SPAN(source, 4, false);
    _az_PRECONDITION_VALID_SPAN(destination, 3, false);
    _az_PRECONDITION_VALID_SPAN(*out_value, 0, false);

    int requiredLen = az_span_size(source) * 3 / 4;

    for (int i = az_span_size(source) - 1; az_span_ptr(source)[i] == '='; i--)
    {
        requiredLen--;
    }

    AZ_RETURN_IF_NOT_ENOUGH_SIZE(destination, requiredLen);

    uint8_t *input = az_span_ptr(source);
    uint8_t *output = az_span_ptr(destination);

    size_t b[4];
    int j = 0;

    for (size_t i = 0; i < az_span_size(source); i += 4)
    {
		b[0] = strchr(CODES, input[i]) - CODES;
		b[1] = strchr(CODES, input[i + 1]) - CODES;
		b[2] = strchr(CODES, input[i + 2]) - CODES;
		b[3] = strchr(CODES, input[i + 3]) - CODES;

		output[j++] = (uint8_t)(((b[0] << 2) | (b[1] >> 4)));

		if (b[2] < 64)
		{
			output[j++] = (uint8_t)(((b[1] << 4) | (b[2] >> 2)));
      
			if (b[3] < 64)  
			{
				output[j++] = (uint8_t)(((b[2] << 6) | b[3]));
			}
		}
    }

    *out_value = az_span_slice(destination, 0, requiredLen);

    return AZ_OK;
}

az_result az_encode_base64(az_span source, az_span destination, az_span *out_value)
{
    _az_PRECONDITION_NOT_NULL(out_value);
    _az_PRECONDITION_VALID_SPAN(source, 1, false);

    int outLen = az_span_size(source);

    outLen += ((3 - (outLen % 3)) % 3);
    outLen = outLen * 4 / 3;

    _az_PRECONDITION_VALID_SPAN(destination, outLen, false);
    _az_PRECONDITION_VALID_SPAN(*out_value, 0, false);

    char b;
    int counter = 0;
    uint8_t *input = az_span_ptr(source);
    uint8_t *output = az_span_ptr(destination);
    int outputLength = az_span_size(destination);

    for (int i = 0; i < az_span_size(source); i += 3)
    {
		b = (input[i] & 0xfc) >> 2;
		output[counter] = CODES[b];
		counter++;

		b = (input[i] & 0x03) << 4;
    
		if (i + 1 < az_span_size(source))      
		{
			b |= (input[i + 1] & 0xF0) >> 4;
			output[counter] = CODES[b];
			counter++;
			b = (input[i + 1] & 0x0F) << 2;
      
			if (i + 2 < az_span_size(source))  
			{
				b |= (input[i + 2] & 0xC0) >> 6;
				output[counter] = CODES[b];
				counter++;
				b = input[i + 2] & 0x3F;
				output[counter] = CODES[b];
				counter++;
			} 
			else  
			{
				output[counter] = CODES[b];
				counter++;
				output[counter] = ('=');
				counter++;
			}
		} 
		else      
		{
			output[counter] = CODES[b];
			counter++;
			output[counter] = '=';
			output[counter + 1] = '=';
			counter += 2;
		}    
	}

    *out_value = az_span_slice(destination, 0, outLen);

    return AZ_OK;
}


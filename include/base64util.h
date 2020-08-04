#pragma once

#include <azure/core/az_span.h>

/**
 * @brief Decodes the \p source from Base64 to the original string in \p destination
 * 
 * @param[in]  Span containing base64 string to be decoded
 * @param[out] Span to receive the decoded string
 * @param[out] Span to receive the calculated length of the output
 * 
 * @returns \ref az_result of AZ_OK if successful
 */
az_result az_decode_base64(az_span source, az_span destination, az_span *out_value);

/**
 * @brief Encodes the \p source to Base64 from the data inputt in \p destination
 * 
 * @param[in]  Span containing base64 string to be encoded
 * @param[out] Span to receive the encoded string
 * @param[out] Span to receive the calculated length of the output
 * 
 * @returns \ref az_result of AZ_OK if successful
 */
az_result az_encode_base64(az_span source, az_span destination, az_span *out_value);
#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

/** Supported encodings. */
typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

/** Encode a Bech32 or Bech32m string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the null-terminated human readable part.
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *      enc:      Which encoding to use (BECH32_ENCODING_BECH32{,M}).
 *  Returns 4 if successful.
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len,
    bech32_encoding enc
);

int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad);

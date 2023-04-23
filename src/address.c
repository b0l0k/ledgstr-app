/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "os.h"
#include "cx.h"

#include "address.h"

#include "transaction/types.h"

#include "common/segwit_addr.h"

void debug_write(char* buf) {
    asm volatile(
        "movs r0, #0x04\n"
        "movs r1, %0\n"
        "svc      0xab\n" ::"r"(buf)
        : "r0", "r1");
}

static int convert_bits(uint8_t* out,
                        size_t* outlen,
                        int outbits,
                        const uint8_t* in,
                        size_t inlen,
                        int inbits,
                        int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t) 1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

bool address_from_pubkey(const uint8_t public_key[static 64], uint8_t* out, size_t out_len) {
    char address[ADDRESS_LEN * 4] = {0};
    // cx_sha3_t keccak256;

    if (out_len < ADDRESS_LEN) {
        return false;
    }

    // cx_keccak_init(&keccak256, 256);
    // cx_hash((cx_hash_t *) &keccak256, CX_LAST, public_key, 64, address, sizeof(address));

    uint8_t data[ADDRESS_LEN * 2];
    size_t datalen = 0;
    if (convert_bits(data, &datalen, 5, public_key, 32, 8, 1) == 0) {
        return false;
    }

    if (bech32_encode(address, "npub", data, datalen, BECH32_ENCODING_BECH32) != 4) {
        return false;
    }

    memmove(out, address, strlen(address));

    return true;
}

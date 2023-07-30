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

#include "helper/bech32.h"
#include "transaction/types.h"

bool address_from_pubkey(const uint8_t public_key[static 64], uint8_t* out, size_t out_len) {
    char address[ADDRESS_BECH32_LEN] = {0};

    if (out_len < ADDRESS_BECH32_LEN) {
        return false;
    }

    uint8_t data[ADDRESS_BECH32_LEN * 2];
    size_t datalen = 0;
    // 32 = Only X
    if (convert_bits(data, &datalen, 5, public_key, 32, 8, 1) == 0) {
        return false;
    }

    if (bech32_encode(address, "npub", data, datalen, BECH32_ENCODING_BECH32) != 4) {
        return false;
    }

    memmove(out, address, strlen(address));

    return true;
}

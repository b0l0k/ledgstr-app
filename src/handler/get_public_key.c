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
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"
#include "crypto_helpers.h"

#include "get_public_key.h"
#include "../globals.h"
#include "../types.h"
#include "../sw.h"
#include "../ui/display.h"
#include "../helper/send_response.h"

const uint32_t pubdefault_path[] = {44 | 0x80000000, 1237 | 0x80000000, 0 | 0x80000000, 0, 0};

int handler_get_public_key(bool display) {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_ADDRESS;
    G_context.state = STATE_NONE;

    uint8_t chain_code[32];
    uint8_t public_key[65];

    cx_err_t error = bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                                 pubdefault_path,
                                                 sizeof(pubdefault_path) / sizeof(pubdefault_path[0]),
                                                 public_key,
                                                 chain_code,
                                                 CX_SHA512);

    memmove(G_context.pk_info.raw_public_key, public_key + 1, 64);
    if (error != CX_OK) {
        return io_send_sw(error);
    }

    if (display) {
        return ui_display_address();
    }

    return helper_send_response_pubkey();
}

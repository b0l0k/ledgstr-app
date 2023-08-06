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
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "crypto.h"

#include "globals.h"

const uint32_t default_path[] = {44 | 0x80000000, 1237 | 0x80000000, 0 | 0x80000000, 0, 0};


int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[32] = {0};
    int error = 0;

    BEGIN_TRY {
        TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;

    return error;
}

int crypto_sign_event(void) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};

    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    // derive private key according to BIP32 path
    int error = crypto_derive_private_key(&private_key,
                                          chain_code,
                                          default_path,
                                          sizeof(default_path) / sizeof(default_path[0]));
    if (error != 0) {
        return error;
    }

    BEGIN_TRY {
        TRY {
            error = cx_ecschnorr_sign_no_throw(&private_key,
                                               CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                               CX_SHA256,
                                               G_context.event_info.m_hash,
                                               32,
                                               sig,
                                               &sig_len);

            memmove(G_context.event_info.signature, sig, sig_len);
            G_context.event_info.signature_len = sig_len;

            PRINTF("Signature: %.*H\n", sig_len, G_context.event_info.signature);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (error == 0) {
        G_context.event_info.signature_len = sig_len;
    }

    return error;
}

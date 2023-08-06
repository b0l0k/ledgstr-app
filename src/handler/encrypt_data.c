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

#include "encrypt_data.h"
#include "../globals.h"
#include "../types.h"
#include "../sw.h"
#include "../ui/display.h"
#include "../ui/action/validate.h"
#include "../helper/send_response.h"

const uint32_t encdefault_path[] = {44 | 0x80000000, 1237 | 0x80000000, 0 | 0x80000000, 0, 0};

int handler_encrypt(buffer_t *cdata, uint8_t chunk, bool more) {
    if (chunk == 0) {  // first APDU, parse peer key
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_ENCRYPT;
        G_context.state = STATE_NONE;

        if (cdata->size != UNCOMPRESSED_RAW_PUBLIC_KEY_LEN) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        G_context.encrypt_info.uncompressed_public_key_peer[0] = 0x04;
        memcpy(G_context.encrypt_info.uncompressed_public_key_peer + 1,
               cdata->ptr,
               sizeof(G_context.encrypt_info.uncompressed_public_key_peer));

        return io_send_sw(SW_OK);
    } else {  // parse transaction

        if (G_context.req_type != CONFIRM_ENCRYPT) {
            return io_send_sw(SW_BAD_STATE);
        }
        if (G_context.encrypt_info.raw_content_len + cdata->size >
            sizeof(G_context.encrypt_info.raw_content)) {
            return io_send_sw(SW_MESSAGE_TOO_LONG);
        }
        if (!buffer_move(
                cdata,
                G_context.encrypt_info.raw_content + G_context.encrypt_info.raw_content_len,
                cdata->size)) {
            return io_send_sw(SW_CONTENT_READING_FAIL);
        }
        G_context.encrypt_info.raw_content_len += cdata->size;

        if (more) {
            // more APDUs with transaction part are expected.
            // Send a SW_OK to signal that we have received the chunk
            return io_send_sw(SW_OK);

        } else {
            cx_err_t ret;

            // Get our private key
            cx_ecfp_private_key_t private_key = {0};
            uint8_t chain_code[32];
            ret = crypto_derive_private_key(&private_key,
                                            chain_code,
                                            encdefault_path,
                                            sizeof(encdefault_path) / sizeof(encdefault_path[0]));

            if (ret != CX_OK) {
                return -1;
            }

            // Get shared secret
            uint8_t secret[32];
            ret = cx_ecdh_no_throw(&private_key,
                                   CX_ECDH_X,
                                   G_context.encrypt_info.uncompressed_public_key_peer,
                                   UNCOMPRESSED_PUBLIC_KEY_LEN,
                                   secret,
                                   sizeof(secret));
            if (ret != CX_OK) {
                return -1;
            }

            // Clean private key from memory
            explicit_bzero(&private_key, sizeof(private_key));

            cx_aes_key_t key;
            cx_err_t err = cx_aes_init_key_no_throw(secret, sizeof(secret), &key);
            if (err != CX_OK) {
                return -11;
            }

            // Clean secret from memory
            explicit_bzero(secret, sizeof(secret));

            G_context.encrypt_info.encrypted_content_len =
                sizeof(G_context.encrypt_info.encrypted_content);
            cx_trng_get_random_data(G_context.encrypt_info.iv, sizeof(G_context.encrypt_info.iv));

            int flag = CX_ENCRYPT | CX_PAD_ISO9797M1 | CX_CHAIN_CBC | CX_LAST;
            err = cx_aes_iv_no_throw(&key,
                                     flag,
                                     G_context.encrypt_info.iv,
                                     sizeof(G_context.encrypt_info.iv),
                                     G_context.encrypt_info.raw_content,
                                     G_context.encrypt_info.raw_content_len,
                                     G_context.encrypt_info.encrypted_content,
                                     &G_context.encrypt_info.encrypted_content_len);

            // Clean key from memory
            explicit_bzero(&key, sizeof(key));

            if (err != CX_OK) {
                return -1;
            }

            uint8_t resp[sizeof(G_context.encrypt_info.encrypted_content_len) + 1 +
                         sizeof(G_context.encrypt_info.iv) +
                         sizeof(G_context.encrypt_info.encrypted_content) + 16] = {0};
            size_t offset = 0;

            memcpy(resp + offset,
                   &G_context.encrypt_info.encrypted_content_len,
                   sizeof(G_context.encrypt_info.encrypted_content_len));
            offset += sizeof(G_context.encrypt_info.encrypted_content_len);

            resp[offset++] = sizeof(G_context.encrypt_info.iv);
            memcpy(resp + offset, G_context.encrypt_info.iv, sizeof(G_context.encrypt_info.iv));
            offset += sizeof(G_context.encrypt_info.iv);

            memcpy(resp + offset,
                   G_context.encrypt_info.encrypted_content,
                   G_context.encrypt_info.encrypted_content_len);
            offset += G_context.encrypt_info.encrypted_content_len;

            return io_send_framed_response(
                &(const buffer_t){.ptr = resp, .size = offset, .offset = 0});
        }
    }
    return 0;
}

int handler_decrypt(buffer_t *cdata, uint8_t chunk, bool more) {
    if (chunk == 0) {  // first APDU, parse peer key
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_DECRYPT;
        G_context.state = STATE_NONE;

        if (cdata->size != UNCOMPRESSED_RAW_PUBLIC_KEY_LEN) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        G_context.encrypt_info.uncompressed_public_key_peer[0] = 0x04;
        memcpy(G_context.encrypt_info.uncompressed_public_key_peer + 1,
               cdata->ptr,
               sizeof(G_context.encrypt_info.uncompressed_public_key_peer));

        return io_send_sw(SW_OK);
    } else if (chunk == 1) {  // first APDU, parse peer key
        if (G_context.req_type != CONFIRM_DECRYPT) {
            return io_send_sw(SW_BAD_STATE);
        }

        if (cdata->size != IV_LEN) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        memcpy(G_context.encrypt_info.iv, cdata->ptr, sizeof(G_context.encrypt_info.iv));

        return io_send_sw(SW_OK);
    } else {
        if (G_context.req_type != CONFIRM_DECRYPT) {
            return io_send_sw(SW_BAD_STATE);
        }
        if (G_context.encrypt_info.encrypted_content_len + cdata->size >
            sizeof(G_context.encrypt_info.encrypted_content)) {
            return io_send_sw(SW_MESSAGE_TOO_LONG);
        }
        if (!buffer_move(cdata,
                         G_context.encrypt_info.encrypted_content +
                             G_context.encrypt_info.encrypted_content_len,
                         cdata->size)) {
            return io_send_sw(SW_CONTENT_READING_FAIL);
        }
        G_context.encrypt_info.encrypted_content_len += cdata->size;

        if (more) {
            // more APDUs with transaction part are expected.
            // Send a SW_OK to signal that we have received the chunk
            return io_send_sw(SW_OK);

        } else {
            cx_err_t ret;

            // Get our private key
            cx_ecfp_private_key_t private_key = {0};
            uint8_t chain_code[32];
            ret = crypto_derive_private_key(&private_key,
                                            chain_code,
                                            encdefault_path,
                                            sizeof(encdefault_path) / sizeof(encdefault_path[0]));

            if (ret != CX_OK) {
                return -1;
            }

            // Get shared secret
            uint8_t secret[32];
            ret = cx_ecdh_no_throw(&private_key,
                                   CX_ECDH_X,
                                   G_context.encrypt_info.uncompressed_public_key_peer,
                                   UNCOMPRESSED_PUBLIC_KEY_LEN,
                                   secret,
                                   sizeof(secret));
            if (ret != CX_OK) {
                return -1;
            }

            // Clean private key from memory
            explicit_bzero(&private_key, sizeof(private_key));

            cx_aes_key_t key;
            cx_err_t err = cx_aes_init_key_no_throw(secret, sizeof(secret), &key);
            if (err != CX_OK) {
                return -11;
            }

            // Clean secret from memory
            explicit_bzero(secret, sizeof(secret));

            G_context.encrypt_info.raw_content_len = sizeof(G_context.encrypt_info.raw_content);
            int flag = CX_DECRYPT | CX_CHAIN_CBC;
            err = cx_aes_iv_no_throw(&key,
                                     flag,
                                     G_context.encrypt_info.iv,
                                     sizeof(G_context.encrypt_info.iv),
                                     G_context.encrypt_info.encrypted_content,
                                     G_context.encrypt_info.encrypted_content_len,
                                     G_context.encrypt_info.raw_content,
                                     &G_context.encrypt_info.raw_content_len);

            // Clean key from memory
            explicit_bzero(&key, sizeof(key));

            if (err != CX_OK) {
                return -1;
            }

            uint8_t resp[sizeof(G_context.encrypt_info.raw_content_len) +
                         sizeof(G_context.encrypt_info.raw_content) + 16] = {0};
            size_t offset = 0;

            memcpy(resp + offset,
                   &G_context.encrypt_info.raw_content_len,
                   sizeof(G_context.encrypt_info.raw_content_len));
            offset += sizeof(G_context.encrypt_info.raw_content_len);

            memcpy(resp + offset,
                   G_context.encrypt_info.raw_content,
                   G_context.encrypt_info.raw_content_len);
            offset += G_context.encrypt_info.raw_content_len;

            return io_send_framed_response(&(buffer_t){.ptr = resp, .size = offset, .offset = 0});
        }
    }
    return 0;
}

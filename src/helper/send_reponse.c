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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <string.h>  // memmove

#include "send_response.h"
#include "../constants.h"
#include "../globals.h"
#include "../sw.h"

int helper_send_response_pubkey() {
    uint8_t resp[1 + 1 + PUBKEY_LEN] = {0};
    size_t offset = 0;

    resp[offset++] = PUBKEY_LEN + 1;
    resp[offset++] = 0x04;
    memmove(resp + offset, G_context.pk_info.raw_public_key, PUBKEY_LEN);
    offset += PUBKEY_LEN;

    return io_send_response_buffer(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0}, SW_OK);
}

int helper_send_response_event() {
    uint8_t resp[1 + 800 + 1] = {0};
    size_t offset = 0;

    resp[offset++] = G_context.event_info.signature_len;
    memmove(resp + offset, G_context.event_info.signature, G_context.event_info.signature_len);
    offset += G_context.event_info.signature_len;

    return io_send_response_buffer(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0}, SW_OK);
}

int io_send_framed_response(const buffer_t *rdata) {
    if (G_context.state == STATE_IN_TRANSFER)
        return -1;  // io_send_framed_response_continue must be used.

    if (rdata == NULL || rdata->size - rdata->offset <= IO_APDU_BUFFER_SIZE - 2)
        return io_send_response_buffer(rdata, SW_OK);

    G_context.state = STATE_IN_TRANSFER;
    G_context.in_transfer =
        (const buffer_t){.ptr = rdata->ptr, .size = rdata->size, .offset = rdata->offset};

    buffer_t frame = (const buffer_t){.ptr = G_context.in_transfer.ptr,
                                      .size = IO_APDU_BUFFER_SIZE - 2,
                                      .offset = G_context.in_transfer.offset};
    G_context.in_transfer.offset += IO_APDU_BUFFER_SIZE - 2;

    return io_send_response_buffer(&frame, SW_OK_MORE_DATA_AVAILABLE);
}

int io_send_framed_response_continue() {
    if (G_context.state != STATE_IN_TRANSFER)
        return -1;  // io_send_framed_response must be used before.

    if (G_context.in_transfer.size - G_context.in_transfer.offset <= IO_APDU_BUFFER_SIZE - 2) {
        return io_send_response_buffer(&G_context.in_transfer, SW_OK);
    }

    buffer_t frame = (const buffer_t){.ptr = G_context.in_transfer.ptr,
                                      .size = IO_APDU_BUFFER_SIZE - 2,
                                      .offset = G_context.in_transfer.offset};

    G_context.in_transfer.offset += IO_APDU_BUFFER_SIZE - 2;

    return io_send_response_buffer(&frame, SW_OK_MORE_DATA_AVAILABLE);
}
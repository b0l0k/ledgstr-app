#pragma once

#include "os.h"
#include "io.h"

#include "buffer.h"

/**
 * Length of public key.
 */
#define PUBKEY_LEN (MEMBER_SIZE(pubkey_ctx_t, raw_public_key))

int helper_send_response_pubkey(void);

int helper_send_response_event(void);

int io_send_framed_response(const buffer_t *rdata);

int io_send_framed_response_continue(void);

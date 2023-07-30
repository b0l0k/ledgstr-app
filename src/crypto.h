
#pragma once

#include <stdint.h>  // uint*_t

#include "os.h"
#include "cx.h"


int crypto_sign_event(void);

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len);

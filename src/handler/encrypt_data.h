#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"
#include "buffer.h"

int handler_encrypt(buffer_t *cdata, uint8_t chunk, bool more);

int handler_decrypt(buffer_t *cdata, uint8_t chunk, bool more);
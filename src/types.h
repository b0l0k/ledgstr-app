#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "transaction/types.h"
#include "common/bip32.h"
#include "common/buffer.h"

/**
 * Enumeration for the status of IO.
 */
typedef enum {
    READY,     /// ready for new event
    RECEIVED,  /// data received
    WAITING    /// waiting
} io_state_e;

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,     /// version of the application
    GET_APP_NAME = 0x04,    /// name of the application
    GET_PUBLIC_KEY = 0x05,  /// public key of corresponding BIP32 path
    SIGN_EVENT = 0x07,
    ENCRYPT_DATA = 0x08,
    DECRYPT_DATA = 0x09,
    GET_RESPONSE = 0xC0
} command_e;

/**
 * Structure with fields of APDU command.
 */
typedef struct {
    uint8_t cla;    /// Instruction class
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
    uint8_t lc;     /// Length of command data
    uint8_t *data;  /// Command data
} command_t;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,      /// No state
    STATE_APPROVED,  /// Transaction data approved
    STATE_IN_TRANSFER
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum { CONFIRM_ADDRESS, CONFIRM_EVENT, CONFIRM_ENCRYPT, CONFIRM_DECRYPT } request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[64];  /// x-coordinate (32), y-cooedinate (32)
} pubkey_ctx_t;

typedef struct {
    uint8_t m_hash[32];                  /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
} event_ctx_t;

typedef struct {
    uint8_t raw_content[MAX_CONTENT_LEN];
    size_t raw_content_len;
    uint8_t uncompressed_public_key_peer[UNCOMPRESSED_PUBLIC_KEY_LEN];
    uint8_t encrypted_content[MAX_ENCRYPTED_CONTENT_LEN];
    size_t encrypted_content_len;
    uint8_t iv[IV_LEN];
} encrypt_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;
        event_ctx_t event_info;
        encrypt_ctx_t encrypt_info;
    };
    buffer_t in_transfer;
    request_type_e req_type;  /// user request
} global_ctx_t;

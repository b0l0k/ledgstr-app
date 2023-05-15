#pragma once

/**
 * Instruction class of the Boilerplate application.
 */
#define CLA 0xE0

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

#define AES_BLOCK_SIZE 16

#define MAX_CONTENT_LEN AES_BLOCK_SIZE * 10

#define MAX_ENCRYPTED_CONTENT_LEN MAX_CONTENT_LEN

#define IV_LEN AES_BLOCK_SIZE

#define EVENT_HASH_LEN 32

#define UNCOMPRESSED_RAW_PUBLIC_KEY_LEN 64

#define UNCOMPRESSED_PUBLIC_KEY_LEN (1 + UNCOMPRESSED_RAW_PUBLIC_KEY_LEN)  // format(1)

/**
 * Maximum signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

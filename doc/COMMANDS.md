# Boilerplate commands

## Overview

| Command name | INS | Description |
| --- | --- | --- |
| `GET_VERSION` | 0x03 | Get application version as `MAJOR`, `MINOR`, `PATCH` |
| `GET_APP_NAME` | 0x04 | Get ASCII encoded application name |
| `GET_PUBLIC_KEY` | 0x05 | Get public key |
| `SIGN_EVENT` | 0x07 | Sign event (hash only) |
| `ENCRYPT_DATA` | 0x08 | Encrypt data |
| `DECRYPT_DATA` | 0x09 | Decrypt data |
| `GET_RESPONSE` | 0xC0 | Get next response chunk |

## GET_VERSION

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x03 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 3 | 0x9000 | `MAJOR (1)` \|\| `MINOR (1)` \|\| `PATCH (1)` |

## GET_APP_NAME

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x04 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `APPNAME (var)` |

## GET_PUBLIC_KEY

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x05 | 0x00 (no display) <br> 0x01 (display) | 0x00 | 0x00 |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(public_key) (1)` \|\|<br> `public_key (var)` \|\|

## SIGN_EVENT

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x07 | 0x00 (no display) <br> 0x01 (display) | 0x00 | 32 | `event_hash (32)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(signature) (1)` \|\| <br> `signature (var)` \|\| <br> `v (1)`|

## Status Words

| SW | SW name | Description |
| --- | --- | --- |
| 0x6985 | `SW_DENY` | Rejected by user |
| 0x6A86 | `SW_WRONG_P1P2` | Either `P1` or `P2` is incorrect |
| 0x6A87 | `SW_WRONG_DATA_LENGTH` | `Lc` or minimum APDU length is incorrect |²
| 0x6D00 | `SW_INS_NOT_SUPPORTED` | No command exists with `INS` |
| 0x6E00 | `SW_CLA_NOT_SUPPORTED` | Bad `CLA` used for this application |
| 0xB000 | `SW_WRONG_RESPONSE_LENGTH` | Wrong response length (buffer size problem) |
| 0xB002 | `SW_DISPLAY_ADDRESS_FAIL` | Address conversion to string failed |
| 0xB004 | `SW_MESSAGE_TOO_LONG` | Maximum message size limit reached |
| 0xB007 | `SW_BAD_STATE` | Security issue with bad state |
| 0xB008 | `SW_SIGNATURE_FAIL` | Signature failed |
| 0x6100 | `SW_OK_MORE_DATA_AVAILABLE` | More data available, use `GET_RESPONSE` command to get next bytes |
| 0x9000 | `OK` | Success |

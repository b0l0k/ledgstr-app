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

#ifdef HAVE_NBGL

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../sw.h"
#include "../address.h"
#include "action/validate.h"
#include "../transaction/types.h"
#include "../menu.h"

static char g_address[64];
static char g_event[65];

static nbgl_layoutTagValue_t pairs[1];
static nbgl_layoutTagValueList_t pairList;

static void confirm_address_rejection(void) {
    // display a status page and go back to main
    validate_pubkey(false);
    nbgl_useCaseStatus("Address verification\ncancelled", false, ui_menu_main);
}

static void confirm_address_approval(void) {
    // display a success status page and go back to main
    validate_pubkey(true);
    nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_menu_main);
}

static void review_choice(bool confirm) {
    if (confirm) {
        confirm_address_approval();
    } else {
        confirm_address_rejection();
    }
}

static void continue_review(void) {
    // Fill pairs
    pairs[0].item = "Address";
    pairs[0].value = g_address;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;
    nbgl_useCaseAddressConfirmationExt(g_address, review_choice, &pairList);
}

int ui_display_address() {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_address, 0, sizeof(g_address));
    uint8_t address[ADDRESS_BECH32_LEN] = {0};
    if (!address_from_pubkey(G_context.pk_info.raw_public_key, address, sizeof(address))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }
    snprintf(g_address, sizeof(g_address), "%s", address);

    nbgl_useCaseReviewStart(&C_warning64px,
                            "Verify address",
                            NULL,
                            "Cancel",
                            continue_review,
                            confirm_address_rejection);
    return 0;
}

static nbgl_pageInfoLongPress_t infoLongPress;

static void confirm_transaction_rejection(void) {
    // display a status page and go back to main
    validate_event(false);
    nbgl_useCaseStatus("Transaction rejected", false, ui_menu_main);
}

static void ask_transaction_rejection_confirmation(void) {
    // display a choice to confirm/cancel rejection
    nbgl_useCaseConfirm("Reject transaction?",
                        NULL,
                        "Yes, Reject",
                        "Go back to transaction",
                        confirm_transaction_rejection);
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice_event_hash(bool confirm) {
    if (confirm) {
        // display a status page and go back to main
        validate_event(true);
        nbgl_useCaseStatus("TRANSACTION\nSIGNED", true, ui_menu_main);
    } else {
        ask_transaction_rejection_confirmation();
    }
}

static void review_continue_event_hash(void) {
    // Setup data to display
    pairs[0].item = "Hash";
    pairs[0].value = g_event;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    // Info long press
    infoLongPress.icon = &C_warning64px;
    infoLongPress.text = "Sign event";
    infoLongPress.longPressText = "Hold to sign";

    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Reject", review_choice_event_hash);
}

// Public function to start the transaction review
// - Check if the app is in the right state for transaction review
// - Format the amount and address strings in g_amount and g_address buffers
// - Display the first screen of the transaction review
int ui_display_event() {
    if (G_context.req_type != CONFIRM_EVENT) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_event, 0, sizeof(g_event));
    snprintf(g_event, sizeof(g_event), "0x%.*H", EVENT_HASH_LEN, G_context.event_info.m_hash);

    // Start review
    nbgl_useCaseReviewStart(&C_warning64px,
                            "Review event hash\nto send on Nostr network",
                            NULL,
                            "Reject",
                            review_continue_event_hash,
                            ask_transaction_rejection_confirmation);
    return 0;
}
#endif
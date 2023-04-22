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

#include "get_public_key.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../crypto.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../ui/action/validate.h"


int handler_sign_event(buffer_t *cdata, bool display) {

    if(cdata->size != 32){
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_EVENT;
    G_context.state = STATE_NONE;

    memmove(G_context.event_info.m_hash, cdata->ptr, cdata->size);

    if (display) {
            return ui_display_event();
    }

    return validate_event(true);
}

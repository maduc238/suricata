/* Copyright (C) 2015-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-diameter.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Diameter.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-diameter.h"
#include "output-json-diameter.h"

typedef struct LogDiameterFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogDiameterFileCtx;

typedef struct LogDiameterLogThread_ {
    LogDiameterFileCtx *diameterlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogDiameterLogThread;

static int JsonDiameterLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    DiameterTransaction *diametertx = tx;
    LogDiameterLogThread *thread = thread_data;

    // SCLogNotice("Logging diameter transaction %"PRIu64".", diametertx->tx_id);

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "diameter", NULL, thread->diameterlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "diameter");

    /* Log the message buffer. */
    if (diametertx->data != NULL) {
        jb_set_string_from_bytes(js, "request", diametertx->data,
                diametertx->data_len);
    }

    /* Close diameter. */
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputDiameterLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDiameterFileCtx *diameterlog_ctx = (LogDiameterFileCtx *)output_ctx->data;
    SCFree(diameterlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputDiameterLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogDiameterFileCtx *diameterlog_ctx = SCCalloc(1, sizeof(*diameterlog_ctx));
    if (unlikely(diameterlog_ctx == NULL)) {
        return result;
    }
    diameterlog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(diameterlog_ctx);
        return result;
    }
    output_ctx->data = diameterlog_ctx;
    output_ctx->DeInit = OutputDiameterLogDeInitCtxSub;

    SCLogNotice("Diameter log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DIAMETER);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonDiameterLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDiameterLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogDiameter.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->diameterlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->diameterlog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonDiameterLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDiameterLogThread *thread = (LogDiameterLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDiameterLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDiameterLog", "eve-log.diameter",
            OutputDiameterLogInitSub, ALPROTO_DIAMETER, JsonDiameterLogger,
            JsonDiameterLogThreadInit, JsonDiameterLogThreadDeinit, NULL);

    SCLogNotice("Diameter JSON logger registered.");
}

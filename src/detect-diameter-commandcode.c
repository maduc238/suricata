/* Copyright (C) 2015-2018 Open Information Security Foundation
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
 * TODO: Update the \author in this file and detect-diameter-commandcode.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author Ma Duc <mavietduc@gmail.com>
 *
 * Set up of the "diameter.commandcode" keyword to allow content
 * inspections on the decoded diameter application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-diameter.h"
#include "detect-diameter-commandcode.h"

static int DetectDiameterCommandCodeSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
static int DetectDiameterMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static void DetectDiameterCommandcodeFree(DetectEngineCtx *de_ctx, void *ptr);
#ifdef UNITTESTS
static void DetectDiameterCommandCodeRegisterTests(void);
#endif
static int g_diameter_commandcode_id = 0;

void DetectDiameterCommandCodeRegister(void)
{
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].name = "diameter.commandcode";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].desc = "Match on Diameter Command Code";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].url = "/rules/diameter-keywords/html#diameter.commandcode";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].AppLayerTxMatch = DetectDiameterMatch;
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].Setup = DetectDiameterCommandCodeSetup;
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].Free = DetectDiameterCommandcodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].RegisterTests =
        DetectDiameterCommandCodeRegisterTests;
#endif

    // sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].flags |= SIGMATCH_NOOPT;

    /*
    DetectAppLayerInspectEngineRegister2("diameter.commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOSERVER, 0, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("diameter.commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("diameter.commandcode", SIG_FLAG_TOSERVER, 0, PrefilterGenericMpmRegister, GetData, ALPROTO_DIAMETER, 0);
    DetectAppLayerMpmRegister2("diameter.commandcode", SIG_FLAG_TOCLIENT, 0, PrefilterGenericMpmRegister, GetData, ALPROTO_DIAMETER, 0);
    */

    g_diameter_commandcode_id = DetectBufferTypeRegister("diameter.commandcode");

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogDebug("Diameter application layer detect registered.");
}

static void DetectDiameterCommandcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

/**
 * \brief This function is used to parse ssl_version data passed via
 *        keyword: "ssl_version"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided options
 *
 * \retval ssl pointer to DetectSslVersionData on success
 * \retval NULL on failure
 */

static DetectDiameterCommandcodeData *DetectDiameterCommandcodeParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCLogDebug("Run Command Code Parse");
    DetectDiameterCommandcodeData *dcc = NULL;
    const char *tmp_str = str;
    size_t tmp_len = 0;
    uint8_t found = 0;

    /* We have a correct diameter command code options */
    dcc = SCCalloc(1, sizeof(DetectDiameterCommandcodeData));
    if (unlikely(dcc == NULL))
        goto error;

    // skip leading space
    while (isspace(tmp_str[0])) {
        tmp_str++;
    }

    // "code: 123,456,78,910,"
    uint32_t num = 0;
    uint16_t len = 0;
    while (1) {
        while (!isspace(tmp_str[tmp_len]) && tmp_str[tmp_len] != ',') {
            num = num * 10;
            num += (uint32_t)tmp_str[tmp_len] - 48;
            tmp_len++;
        }
        CommandCode *cmcode = SCCalloc(1, sizeof(CommandCode));
        SCLogDebug("Insert Command Code rules: %"PRIu32, num);
        cmcode->commandcode = num;
        TAILQ_INSERT_TAIL(&dcc->commandcode_list, cmcode, next);
        num = 0;
        tmp_len++;
        if (tmp_str[tmp_len] == 0) break;
    }

    return dcc;

error:
    if (dcc != NULL)
        DetectDiameterCommandcodeFree(de_ctx, dcc);
    return NULL;

}


/**
 * \brief Hàm setup detect Command Code của Diameter
 * 
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided diameter.commandcode options
 * 
 * \retval 0 on Success
 * \retval -1 on Failure
*/
static int DetectDiameterCommandCodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogDebug("Run Command Code Setup");
    DetectDiameterCommandcodeData *dcc = NULL;
    SigMatch *sm = NULL;

    sm = SCCalloc(1, sizeof(SigMatch));
    
    /* store list id. Content, pcre, etc will be added to the list at this id. */
    s->init_data->list = g_diameter_commandcode_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_DIAMETER */
    if (DetectSignatureSetAppProto(s, ALPROTO_DIAMETER) != 0)
        return -1;

    dcc = DetectDiameterCommandcodeParse(de_ctx, str);
    if (dcc == NULL)
        goto error;

    sm->type = DETECT_AL_DIAMETER_COMMANDCODE;
    sm->ctx = (void *)dcc;

    SigMatchAppendSMToList(s, sm, g_diameter_commandcode_id);

    return 0;

error:
    if (dcc != NULL)
        DetectDiameterCommandcodeFree(de_ctx, dcc);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
/*
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const DiameterTransaction  *tx = (DiameterTransaction *)txv;
        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        data = tx->data;
        data_len = tx->data_len;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}*/

/**
 * \brief This function is used to match Diameter code on a transaction with via diameter.commandcode:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectDiameterMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    SCEnter();

    SCLogNotice("Run Match ...");

    const DiameterState *dstate = (DiameterState *) state;
    const DetectDiameterCommandcodeData *dcc = (DetectDiameterCommandcodeData *) ctx;
    DiameterTransaction *tx = txv;
    if (tx->data_len <= 20) SCReturn(0);
    DiameterMessageHeader mess = ReadDiameterHeaderData(tx->data, tx->data_len);
    
    uint32_t commandcode = mess.CommandCode;

    CommandCode *cmcode;
    TAILQ_FOREACH(cmcode, &dcc->commandcode_list, next) {
        if (cmcode->commandcode == commandcode) {
            SCLogNotice("Found Command Code: %"PRIu32, cmcode->commandcode);
            SCReturn(1);
        }
    }
    SCReturn(0);
}

#ifdef UNITTESTS
#include "tests/detect-diameter-commandcode.c"
#endif

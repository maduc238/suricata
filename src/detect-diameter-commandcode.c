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
#ifdef UNITTESTS
static void DetectDiameterCommandCodeRegisterTests(void);
#endif
static int g_diameter_commandcode_id = 0;

void DetectDiameterCommandCodeRegister(void)
{
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].name = "diameter.commandcode";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].desc = "match on Diameter Command Code";
    // sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].AppLayerTxMatch = DetectDiameterMatch;
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].Setup = DetectDiameterCommandCodeSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].RegisterTests =
        DetectDiameterCommandCodeRegisterTests;
#endif

    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
    DetectAppLayerInspectEngineRegister2("diameter.commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOSERVER, 0, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("diameter.commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectBufferGeneric, GetData);

    /* register mpm engines - these are called in the prefilter stage */
    DetectAppLayerMpmRegister2("diameter.commandcode", SIG_FLAG_TOSERVER, 0, PrefilterGenericMpmRegister, GetData, ALPROTO_DIAMETER, 0);
    DetectAppLayerMpmRegister2("diameter.commandcode", SIG_FLAG_TOCLIENT, 0, PrefilterGenericMpmRegister, GetData, ALPROTO_DIAMETER, 0);


    g_diameter_commandcode_id = DetectBufferTypeGetByName("diameter.commandcode");

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogDebug("Diameter application layer detect registered.");
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
    /* store list id. Content, pcre, etc will be added to the list at this id. */
    s->init_data->list = g_diameter_commandcode_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_DIAMETER */
    if (DetectSignatureSetAppProto(s, ALPROTO_DIAMETER) != 0)
        return -1;

    return 0;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
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
}

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
    // const DetectDiameterStateData *ssd = (const DetectSslStateData *)m;
    // DiameterTransaction *tx = txv;
    // if (ctx->data_len <= 20) return 0;
    // DiameterMessageHeader mess ReadDiameterHeaderData(tx->data, tx->data_len);
    // if (mess)

    return 0;
}

#ifdef UNITTESTS
#include "tests/detect-diameter-commandcode.c"
#endif

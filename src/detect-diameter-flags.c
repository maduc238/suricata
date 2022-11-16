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
 * TODO: Update the \author in this file and detect-diameter-flags.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "diameter_flags" keyword to allow content
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
#include "detect-diameter-flags.h"

DiameterFlagKeywords DiameterFlagsKeywordsList[MAX_NUM_FLAG] = {
    {"t", T_FLAG_POSIONTION, DIAMETER_FLAG_T},
    {"e", E_FLAG_POSIONTION, DIAMETER_FLAG_E},
    {"p", P_FLAG_POSIONTION, DIAMETER_FLAG_P},
    {"r", R_FLAG_POSIONTION, DIAMETER_FLAG_R},
};

static int DetectDiameterflagsSetup(DetectEngineCtx *, Signature *, const char *);
static DiameterFlagsData* DetectDiameterFlagsParseSign(DetectEngineCtx *de_ctx, const char *sign);
static void DetectDiameterFlagsFree(DetectEngineCtx *de_ctx, void *ptr);
static int DiameterFlagsMatch(DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
// static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
//         const DetectEngineTransforms *transforms,
//         Flow *_f, const uint8_t flow_flags,
//         void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectDiameterFlagsRegisterTests(void);
#endif
static int g_diameter_flags_id = 0;

void DetectDiameterFlagsRegister(void)
{
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].name = "diameter_flags";
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].desc =
            "Diameter content modifier to match on the diameter buffers";
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].Setup = DetectDiameterflagsSetup;
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].AppLayerTxMatch = DiameterFlagsMatch;
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].Free  = DetectDiameterFlagsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DIAMETER_FLAGS].RegisterTests =
        DetectDiameterFlagsRegisterTests;
#endif

    // sigmatch_table[DETECT_AL_DIAMETER_FLAGS].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
    // DetectAppLayerInspectEngineRegister2("diameter_flags",
    //         ALPROTO_DIAMETER, SIG_FLAG_TOSERVER, 0,
    //         DetectEngineInspectBufferGeneric, GetData);
    // DetectAppLayerInspectEngineRegister2("diameter_flags",
    //         ALPROTO_DIAMETER, SIG_FLAG_TOCLIENT, 0,
    //         DetectEngineInspectBufferGeneric, GetData);

    // /* register mpm engines - these are called in the prefilter stage */
    // DetectAppLayerMpmRegister2("diameter_flags", SIG_FLAG_TOSERVER, 0,
    //         PrefilterGenericMpmRegister, GetData,
    //         ALPROTO_DIAMETER, 0);
    // DetectAppLayerMpmRegister2("diameter_flags", SIG_FLAG_TOCLIENT, 0,
    //         PrefilterGenericMpmRegister, GetData,
    //         ALPROTO_DIAMETER, 0);


    g_diameter_flags_id = DetectBufferTypeGetByName("diameter_flags");

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogNotice("Diameter application layer detect flags registered.");
}


static int DetectDiameterflagsSetup(DetectEngineCtx *de_ctx, Signature *s, const char *sign)
{
    DiameterFlagsData* flags = NULL;
    SigMatch *sm = NULL;

    s->init_data->list = g_diameter_flags_id;
    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_DIAMETER */
    if (DetectSignatureSetAppProto(s, ALPROTO_DIAMETER) != 0)
        return -1;

    flags = DetectDiameterFlagsParseSign(de_ctx, sign);
    if (flags == NULL)
        goto error;
    sm = SigMatchAlloc();

    if (sm == NULL)
        goto error;
    
    sm->type = DETECT_AL_DIAMETER_FLAGS;
    sm->ctx = (void *)flags;
    SigMatchAppendSMToList(s, sm, g_diameter_flags_id);
    SCLogNotice("flagsetupaa");
    return 0;
error:
    if (flags != NULL)
        DetectDiameterFlagsFree(de_ctx, flags);
    if (sm != NULL)
        SCFree(sm);
    return -1;
    return 0;
}


static DiameterFlagsData* DetectDiameterFlagsParseSign(DetectEngineCtx *de_ctx, const char *sign) {
    SCLogNotice("parsesign");
    DiameterFlagsData *flags = NULL;
    const char* tmp_sign = sign;

    size_t tmp_len = 0;

    flags = SCCalloc(1, sizeof(DiameterFlagsData));
    if (unlikely(flags == NULL))
        goto error;
    *flags = 0;

    while (tmp_sign[0] != 0 && isspace(tmp_sign[0])) 
        tmp_sign++;   

    if (tmp_sign[0] == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid empty value");
        goto error;
    }

    while (tmp_sign[0] != 0) {
        uint8_t neg = 0;
        if (tmp_sign[0] == '!') {
            neg = 1;
            tmp_sign++;
        }
        // counts word length
        tmp_len = 0;
        while (tmp_sign[tmp_len] != 0 && !isspace(tmp_sign[tmp_len]) && tmp_sign[tmp_len] != ',') {
            tmp_len++;
        }

        bool is_keyword = false;    
        for (size_t i = 0; i < MAX_NUM_FLAG; i++) {
            if (tmp_len == 1 && strncasecmp(DiameterFlagsKeywordsList[i].keyWord, tmp_sign, tmp_len) == 0) {
                if (neg != 1)
                    *flags |= DiameterFlagsKeywordsList[i].value;
    
                is_keyword = true;
                break;
            }
        }
        if (!is_keyword) {
            SCLogError(SC_ERR_INVALID_VALUE, "Invalid unknown value");
            goto error;
        }

        tmp_sign += 1;
        while (isspace(tmp_sign[0]) || tmp_sign[0] == ',') {
            tmp_sign++;
        }
    }
    return flags;
error:
    if (flags != NULL)
        DetectDiameterFlagsFree(de_ctx, flags);
    return NULL;
} 

static int DiameterFlagsMatch(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCLogNotice("flagsmatch");
    SCEnter();

    uint32_t flag = 0;

    const DiameterFlagsData *signFlags = (const DiameterFlagsData *)m;
    DiameterState *app_state = (DiameterState *)state;
    if (app_state == NULL) {
        SCLogDebug("no diameter app state, no match");
        SCReturnInt(0);
    }

    DiameterTransaction *ttx = (DiameterTransaction*) txv;
    flag =  (DiameterFlagsData)ttx->data[4];

    if (flag == *signFlags) 
        SCReturn(1);
    SCReturn(0);
}

void DetectDiameterFlagsFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
// static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
//         const DetectEngineTransforms *transforms,
//         Flow *_f, const uint8_t flow_flags,
//         void *txv, const int list_id)
// {
//     InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
//     if (buffer->inspect == NULL) {
//         const DiameterTransaction  *tx = (DiameterTransaction *)txv;
//         const uint8_t *data = NULL;
//         uint32_t data_len = 0;

//         if (flow_flags) {
//             data = tx->data;
//             data_len = tx->data_len;
//         } else {
//             return NULL; /* no buffer */
//         }

//         InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
//         InspectionBufferApplyTransforms(buffer, transforms);
//     }

//     return buffer;
// }

#ifdef UNITTESTS
#include "tests/detect-diameter-flags.c"
#endif

/* Copyright (C) 2015-2022 Open Information Security Foundation
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

/**
 * \file detect-diameter-commandcode.c
 *
 * \author Ma Duc <mavietduc@gmail.com>
 *
 * Thiết lập diameter_commandcode keyword để lọc những gói tin
 * Diameter có command code tương ứng
 * 
 * Ví dụ:
 * alert diameter any any -> any any (msg:"Diameter Command Code"; diameter_commandcode:257,316, ; sid:1;)
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
static int DetectDiameterMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
void DetectDiameterCommandcodeFree(DetectEngineCtx *de_ctx, void *ptr);
#ifdef UNITTESTS
static void DetectDiameterCommandCodeRegisterTests(void);
#endif
static int g_diameter_commandcode_id = 0;

void DetectDiameterCommandCodeRegister(void)
{
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].name = "diameter_commandcode";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].desc = "Match on Diameter Command Code";
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].Setup = DetectDiameterCommandCodeSetup;
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].AppLayerTxMatch = DetectDiameterMatch;
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].Free = DetectDiameterCommandcodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].RegisterTests =
        DetectDiameterCommandCodeRegisterTests;
#endif

    // sigmatch_table[DETECT_AL_DIAMETER_COMMANDCODE].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister2("diameter_commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2("diameter_commandcode", ALPROTO_DIAMETER, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    // DetectAppLayerMpmRegister2("diameter_commandcode", SIG_FLAG_TOSERVER, 0, PrefilterGenericMpmRegister, NULL, ALPROTO_DIAMETER, 0);
    // DetectAppLayerMpmRegister2("diameter_commandcode", SIG_FLAG_TOCLIENT, 0, PrefilterGenericMpmRegister, NULL, ALPROTO_DIAMETER, 0);

    g_diameter_commandcode_id = DetectBufferTypeRegister("diameter_commandcode");

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogNotice("Diameter application layer detect Command Code registered.");
}

void DetectDiameterCommandcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCLogNotice("Run Detect Diameter Commandcode Free.");
    if (ptr != NULL)
        SCFree(ptr);
}

/**
 * \brief This function is used to parse diameter_commandcode data passed via
 *        keyword: "diameter_commandcode"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided options
 *
 * \retval diameter pointer to DetectDiameterCommandCodeSetup on success
 * \retval NULL on failure
 */
static DetectDiameterCommandcodeData *DetectDiameterCommandcodeParse(DetectEngineCtx *de_ctx, const char *str)
{
    SCLogNotice("Run Command Code Parse");
    const char *tmp_str = str;
    size_t tmp_len = 0;
    // uint8_t found = 0;

    /* We have a correct diameter command code options */
    DetectDiameterCommandcodeData *dcc = SCCalloc(1, sizeof(DetectDiameterCommandcodeData));
    if (unlikely(dcc == NULL))
        goto error;

    // skip leading space
    // printf("%c\n",tmp_str[0]);
    while (isspace(tmp_str[0])) {
        tmp_str++;
    }

    // "code: 123,456,78,910,"
    uint32_t num = 0;
    // uint16_t len = 0;
    TAILQ_INIT(&dcc->commandcode_list);
    while (1) {
        while (!isspace(tmp_str[tmp_len]) && tmp_str[tmp_len] != ',') {
            num = num * 10;
            num += (uint32_t)tmp_str[tmp_len] - 48;
            tmp_len++;
        }
        CommandCode *cmcode = SCCalloc(1, sizeof(CommandCode));
        SCLogNotice("Insert Command Code rules: %"PRIu32, num);
        TAILQ_INSERT_TAIL(&dcc->commandcode_list, cmcode, next);
        cmcode->commandcode = num;
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
 * \param str pointer to the user provided diameter_commandcode options
 * 
 * \retval 0 on Success
 * \retval -1 on Failure
*/
static int DetectDiameterCommandCodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCLogNotice("Run Command Code Setup");
    DetectDiameterCommandcodeData *dcc = NULL;
    SigMatch *sm = NULL;

    /* store list id. Content, pcre, etc will be added to the list at this id. */
    s->init_data->list = g_diameter_commandcode_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_DIAMETER */
    if (DetectSignatureSetAppProto(s, ALPROTO_DIAMETER) != 0)
        return -1;

    dcc = DetectDiameterCommandcodeParse(de_ctx, str);
    if (dcc == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    
    sm->type = DETECT_AL_DIAMETER_COMMANDCODE;
    sm->ctx = (void *)dcc;

    SigMatchAppendSMToList(s, sm, g_diameter_commandcode_id);
    s->flags |= SIG_FLAG_APPLAYER;

    return 0;

error:
    SCLogNotice("Error while running Command Code Setup");
    if (dcc != NULL)
        DetectDiameterCommandcodeFree(de_ctx, dcc);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief This function is used to match Diameter code on a transaction with via diameter_commandcode:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectDiameterMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    SCEnter();

    const DiameterState *dstate = (DiameterState *) state;
    const DetectDiameterCommandcodeData *dcc = (DetectDiameterCommandcodeData *) ctx;

    if (dstate->data_len <= 20) SCReturnInt(0);
    DiameterMessageHeader mess = ReadDiameterHeaderData(dstate->data, dstate->data_len);
    
    uint32_t commandcode = mess.CommandCode;
    SCLogNotice("Read command code data: %"PRIu32, commandcode);

    CommandCode *cmcode;
    TAILQ_FOREACH(cmcode, &dcc->commandcode_list, next) {
        if (cmcode->commandcode == commandcode) {
            SCReturnInt(1);
        }
    }
    SCReturnInt(0);
}

#ifdef UNITTESTS
#include "tests/detect-diameter-commandcode.c"
#endif

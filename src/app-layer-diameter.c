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
 * TODO: Update \author in this file and app-layer-diameter.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author Ma Duc <mavietduc@gmail.com>
 *
 * Diameter application layer detector and parser for learning and
 * diameter purposes.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "conf.h"
#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-diameter.h"

#include "util-unittest.h"
#include "util-validate.h"
#include "util-enum.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define DIAMETER_DEFAULT_PORT "3868"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define DIAMETER_MIN_FRAME_LEN 20

/**
 * Tổng hợp các event của lớp application cho protocol.
 * Thông thường, có thể xảy ra các event lỗi khi phân tích cú pháp
 * dữ liệu, như dữ liệu được nhận không mong muốn. Với Diameter,
 * chúng ta sẽ tạo ra một thứ nào đó và log lại alert lớp app-layer
 * nếu nhận được một bản tin trống
 * 
 * Ví dụ rule:
 * alert diameter any any -> any any (msg:"SURICATA Diameter empty message"; \
 *    app-layer-event:diameter.empty_message; sid:X; rev:Y;)
*/
enum {
    DIAMETER_DECODER_EVENT_EMPTY_MESSAGE,
    DIAMETER_DECODER_EVENT_ERROR_MESSAGE,
    DIAMETER_SENDING_MESSAGE,
    DIAMETER_RECIVE_SUCCESS_MESSAGE
};

SCEnumCharMap diameter_decoder_event_table[] = {
    {"EMPTY_MESSAGE", DIAMETER_DECODER_EVENT_EMPTY_MESSAGE},
    {"ERROR_MESSAGE", DIAMETER_DECODER_EVENT_ERROR_MESSAGE},
    {"DIAMETER_SENDING",DIAMETER_SENDING_MESSAGE},
    {"DIAMETER_SUCESS",DIAMETER_RECIVE_SUCCESS_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static uint8_t toBinaryAt(uint8_t a, uint8_t point) {
    uint8_t i,j=0;
    uint8_t result[8];
    for(i=0x80;i!=0;i>>=1) {
        result[j] = ((a&i)? 1:0); j++;
    }
    return result[point];
}
DiameterMessageHeader ReadDiameterHeaderData(uint8_t *data, uint32_t data_len) {
    DiameterMessageHeader message;
    if (data_len < 20) return message;
    message.Version = data[0];
    message.Length = data[1]*256*256 + data[2]*256 + data[3];
    message.Flags = data[4];
    message.CommandCode = data[5]*256*256 + data[6]*256 + data[7];
    message.ApplicationId = data[8]*256*256*256 + data[9]*256*256 + data[10]*256 + data[11];
    message.HopbyHopId = data[12]*256*256*256 + data[13]*256*256 + data[14]*256 + data[15];
    message.EndtoEndId = data[16]*256*256*256 + data[17]*256*256 + data[18]*256 + data[19];
    return message;
}

static DiameterTransaction *DiameterTxAlloc(DiameterState *state)
{
    DiameterTransaction *tx = SCCalloc(1, sizeof(DiameterTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is llocated. */
    // state->transaction_max++;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

static void DiameterTxFree(void *txv)
{
    DiameterTransaction *tx = txv;

    if (tx->data != NULL) {
        SCFree(tx->data);
    }

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    SCFree(tx);
}

static void *DiameterStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogNotice("Allocating diameter state.");
    DiameterState *state = SCCalloc(1, sizeof(DiameterState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}
static void DiameterStateFree(void *state)
{
    DiameterState *diameter_state = state;
    DiameterTransaction *tx;
    SCLogNotice("Freeing diameter state.");
    while ((tx = TAILQ_FIRST(&diameter_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&diameter_state->tx_list, tx, next);
        DiameterTxFree(tx);
    }
    SCFree(diameter_state);
}

static int DiameterStateGetEventInfo(const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, diameter_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "diameter enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int DiameterStateGetEventInfoById(int event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, diameter_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "diameter enum map table.",  event_id);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/**
 * \brief Khảo sát xem data đến có là Diameter không.
 *
 * \retval ALPROTO_DIAMETER nếu giống như Diameter,
 *     ALPROTO_FAILED, nếu rõ ràng không phải ALPROTO_DIAMETER,
 *     nếu không thì ALPROTO_UNKNOWN.
 */
static AppProto DiameterProbingParser(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Kiểm tra Diameter ở đây. */
    if (input_len > DIAMETER_MIN_FRAME_LEN) {
        // SCLogNotice("Detected as ALPROTO_DIAMETER");
        return ALPROTO_DIAMETER;
    }
    // SCLogInfo("Protocol not detected as ALPROTO_DIAMETER.");
    return ALPROTO_UNKNOWN;
}

/* Decode bản tin đọc header ở đây */
static AppLayerResult DiameterDecode(Flow *f, uint8_t direction, void *alstate,
        AppLayerParserState *pstate, StreamSlice stream_slice)
{
    DiameterState *state = (DiameterState *)alstate;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
    // const uint8_t flags = StreamSliceGetFlags(&stream_slice);

    if (input == NULL &&
        ((direction == 0 && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) ||
                (direction == 1 &&
                        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)))) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }


    /* Check có đúng là Diameter không */
    DiameterMessageHeader diameter_header = ReadDiameterHeaderData(input, input_len);
    if (diameter_header.Length != input_len) {
        SCLogNotice("Bản tin Diameter nhận diện không đúng");
        SCReturnStruct(APP_LAYER_ERROR);
    }
    SCLogNotice("Parsing diameter message: len=%"PRIu32". CommandCode=%"PRIu32, input_len, diameter_header.CommandCode);
    // SCLogNotice("Transaction max=%"PRIu64, state->transaction_max);

    /* Tạo Tx cho bản tin này */
    DiameterTransaction *tx = DiameterTxAlloc(state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new Diameter tx.");
        goto end;
    }

    /* Make a copy of the message. */
    tx->data = SCCalloc(1, input_len);
    if (unlikely(tx->data == NULL)) {
        goto end;
    }
    memcpy(tx->data, input, input_len);
    tx->data_len = input_len;
end:
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult DiameterParseRequest(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return DiameterDecode(f, 0 /* toserver */, alstate, pstate, stream_slice);
}


static AppLayerResult DiameterParseResponse(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return DiameterDecode(f, 1 /* toclient */, alstate, pstate, stream_slice);
}

static void DiameterStateTxFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static uint64_t DiameterGetTxCnt(void *statev)
{
    const DiameterState *state = statev;
    return state->transaction_max;
}

static int DiameterGetStateProgress(void *txv, uint8_t direction)
{
    DiameterTransaction *tx = txv;

    if (direction & STREAM_TOCLIENT) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        return 1;
    }

    return 0;
}

static void *DiameterGetTx(void *state, uint64_t tx_id)
{
    DiameterState *diameter_state = (DiameterState *)state;
    return diameter_state;
}

/**
 * \brief retrieve the tx data used for logging, config, detection
 */
static AppLayerTxData *DiameterGetTxData(void *vtx)
{
    DiameterTransaction *tx = vtx;
    return &tx->tx_data;
}

/**
 * \brief retrieve the state data
 */
static AppLayerStateData *DiameterGetStateData(void *vstate)
{
    DiameterState *state = vstate;
    return &state->state_data;
}

void RegisterDiameterParsers(void)
{
    const char *proto_name = "diameter";

    /* Check if Diameter TCP detection is enabled. If it does not exist in
     * the configuration file then it will be disabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, false)) {

        SCLogDebug("Diameter TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_DIAMETER, proto_name);

        if (RunmodeIsUnittests()) {
            SCLogNotice("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, DIAMETER_DEFAULT_PORT, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, STREAM_TOSERVER, DiameterProbingParser, NULL);
        }
        else {
            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, DiameterProbingParser, NULL))
            {
                SCLogDebug("No diameter app-layer configuration, enabling echo detection TCP detection on port %s.", DIAMETER_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, DIAMETER_DEFAULT_PORT, ALPROTO_DIAMETER, 0, DIAMETER_MIN_FRAME_LEN, STREAM_TOSERVER, DiameterProbingParser, NULL);
            }

        }

    }

    else {
        SCLogDebug("Protocol detector and parser disabled for Diameter.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogNotice("Registering Diameter protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Diameter flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateAlloc, DiameterStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DIAMETER, STREAM_TOSERVER, DiameterParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DIAMETER, STREAM_TOCLIENT, DiameterParseResponse);

        /* Register a function to be called by the application layer when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_DIAMETER, 1, 1);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterGetStateData);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_DIAMETER, DiameterStateGetEventInfoById);

        /* Leave this is if your parser can handle gaps, otherwise remove. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_DIAMETER, APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogDebug("Diameter protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_DIAMETER,
        DiameterParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void DiameterParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

/*
 * Copyright 2021 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ORDERENTRY_H
#define ORDERENTRY_H

#include "hls_stream.h"
#include "ap_int.h"
#include "aat_defines.hpp"
#include "aat_interfaces.hpp"

#define OE_MSG_LEN_BYTES (256)
#define OE_MSG_WORD_BYTES (8)
#define OE_MSG_NUM_FRAME (OE_MSG_LEN_BYTES / OE_MSG_WORD_BYTES)

#define OE_HALT (1 << 0)
#define OE_RESET_DATA (1 << 1)
#define OE_RESET_COUNT (1 << 2)
#define OE_TCP_CONNECT (1 << 3)
#define OE_TCP_GEN_SUM (1 << 4)
#define OE_CAPTURE_FREEZE (1 << 31)

#define BOX_SUCCESS 23001
#define MS_GR_SUCCESS 2401
#define MS_SIGNON_SUCCESS 2301

#define MS_GR_TCODE 2400
#define BOX_TCODE 23000
#define MS_SIGNON_TCODE 2300

#define PRE_LENGTH 22
#define MS_GR_LENGTH 48
#define BOX_LENGTH 60
#define MS_SIGNON_LENGTH 276
#define MAX_BYTES 1024
//MD5.h 
#define uint64_t ap_uint<64>
#define uint32_t ap_uint<32>
#define uint16_t ap_uint<16>
#define uint8_t unsigned char
#define int64_t ap_int<64>
#define int32_t ap_int<32>
#define size_t ap_uint<64>

typedef struct{
	uint64_t size;        // Size of input in bytes
	uint32_t buffer[4];   // Current accumulation of hash
	uint8_t input[64];    // Input to be used in the next step
	uint8_t digest[16];   // Result of algorithm
}MD5Context;


void md5Init(MD5Context *ctx);
void md5Update(MD5Context *ctx, uint8_t *input, size_t input_len);
void md5Finalize(MD5Context *ctx);
void md5Step(uint32_t *buffer, uint32_t *input);

void md5String(unsigned char *input, unsigned char *output, int length);


typedef struct orderEntryRegControl_t
{
    ap_uint<32> control;
    ap_uint<32> config;
    ap_uint<32> capture;
    ap_uint<32> destAddress;
    ap_uint<32> destPort;
    ap_uint<32> reserved05;
    ap_uint<32> reserved06;
    ap_uint<32> reserved07;
} orderEntryRegControl_t;

typedef struct orderEntryRegStatus_t
{
    ap_uint<32> status;
    ap_uint<32> rxOperation;
    ap_uint<32> processOperation;
    ap_uint<32> txData;
    ap_uint<32> txMeta;
    ap_uint<32> txOrder;
    ap_uint<32> rxData;
    ap_uint<32> rxMeta;
    ap_uint<32> rxEvent;
    ap_uint<32> txDrop;
    ap_uint<32> txStatus;
    ap_uint<32> notification;
    ap_uint<32> readRequest;
    ap_uint<32> debug;
    ap_uint<32> reserved14;
    ap_uint<32> reserved15;
} orderEntryRegStatus_t;

typedef struct connectionStatus_t
{
    ap_uint<1> connected;
    ap_uint<16> length;
    ap_uint<30> space;
    ap_uint<2> error;
    ap_uint<16> sessionID;
} connectionStatus_t;

typedef struct sumOperation_t
{
    ap_uint<16> subSum;
    ap_uint<1> validSum;
} sumOperation_t;

typedef struct orderFields_t
{
    ap_uint<32>TraderId;
    ap_uint<32>branchID;
    ap_uint<32>boxID;
    ap_uint<32>pass1;//first 4 chars
    ap_uint<32>pass2;//last 4 chars
} orderFields_t;


#pragma pack (1)
// message header
struct MESSAGE_HEADER // 40 bytes
{
    ap_uint<16> TransactionCode;
    ap_uint<32> LogTime;
    ap_uint<8> AlphaChar[2];
    ap_uint<32> TraderId;
    ap_uint<16> ErrorCode;
    ap_uint<64> Timestamp;
    ap_uint<64> Timestamp1;
    ap_uint<64> Timestamp2;
    ap_uint<16> MessageLength;
} ;

// gateway router request
struct MS_GR_REQUEST
{
    // MESSAGE_HEADER MESSAGE_HEADER_;
    ap_uint<16> BoxID;
    ap_uint<8> BrokerID[5];
    ap_uint<8> Filler[1];
};

struct PRE_PACKET
{
    ap_uint<16>length;
    ap_uint<32>sequenceNo;
    ap_uint<8>md5checksum[16];
    // unsigned char md5checksum[16];
    // MS_GR_REQUEST payload;
};

// gateway router response
struct MS_GR_RESPONSE
{
    MESSAGE_HEADER MESSAGE_HEADER_;
    ap_int<16> BoxID;
    char BrokerID[5];
    char Filler[1];
    char IPAddress[16];
    ap_int<32> Port;
    char SessionKey[8];
};

struct MS_BOX_SIGN_ON_REQUEST_IN
{
    // MESSAGE_HEADER MESSAGE_HEADER_;
    ap_uint<16> BoxID;
    char BrokerID[5];
    char Reserved[5];
    char SessionKey[8];
};

struct MS_BOX_SIGN_ON_REQUEST_OUT
{
    MESSAGE_HEADER MESSAGE_HEADER_;
    short BoxID;
    char Reserved[10];
};

struct BROKER_ELIGIBILITY_PER_MKT
{
    int Reserved_1:2;
    int CallAuction_2:1;
    int CallAuction_1:1;
    int AuctionMarket:1;
    int SpotMarket:1;
    int OddlotMarket:1;
    int Normal:1;
    int PreOpen:1;
    int Reserved_2:7;
} ;

struct SIGNON
{
    // MESSAGE_HEADER MESSAGE_HEADER_{2300};
    int32_t UserID;
    char Reserved_1[8];
    char Password[8];
    char Reserved_2[8];
    char NewPassword[8];
    char TraderName[26];
    int32_t LastPasswordChangeDate;
    char BrokerID[5];
    char Reserved_3[1];
    ap_int<16> BranchID;
    int32_t VersionNumber;
    char Reserved_4[56];
    ap_int<16> UserType;
    double SequenceNumber;
    char WsClassName[14];
    char BrokerStatus[1];
    char ShowIndex[1];
    BROKER_ELIGIBILITY_PER_MKT br_el_per_mkt;
    char BrokerName[26];
    char Reserved_5[16];
    char Reserved_6[16];
    char Reserved_7[16];
} ;

struct __attribute__((packed)) txn
{
    int transCode;
    char data[MAX_BYTES];
};
struct ORDER
{
    char trans_code[5];
    char user_id[5];
    char account_number[10];
    char book_type[1];
    char buy_sell[1];
    char disclosed_volume[4];
    char volume[4];
    char price[10];
    char trigger_price[10];
    char gtd[10];
    char branch_id[1];
    char symbol[10];
    char series[2];
    char settlor[12];
    char pro_client[1];
    char nnf_field[15];
    char pan[10];
    char transaction_id[5];
    char mod_cxl_by[1];
    char entry_datetime[10];
    char last_modified[10];
    char last_activity_ref[19];
    char order_number[16];
};
struct ST_ORDER_FLAGS 
{
    char MF : 1;             
    char AON : 1;
    char IOC : 1;
    char GTC : 1;
    char Day : 1;
    char OnStop : 1;
    char Market : 1;
    char ATO : 1;
    char Reserved_1 : 1;
    char STPC : 1;
    char Reserved_2 : 1;
    char PreOpen : 1;
    char Frozen : 1;
    char Modified : 1;
    char Traded : 1;
    char MatchedInd : 1;
};

struct SEC_INFO 
{
    char Symbol[10];
    char Series[2];
};

struct OE_REQUEST_TR
{
    short TransactionCode;
    int32_t UserID;
    SEC_INFO sec_info;
    char AccountNumber[10];
    short BookType;
    short BuySell;
    int32_t DisclosedVolume;
    int32_t Volume;
    int32_t Price;
    int32_t GoodTillDate;
    ST_ORDER_FLAGS ST_ORDER_FLAGS_;
    short BranchId;
    int32_t TraderId;
    char BrokerId[5];
    char Suspended;
    char Settlor[12];
    short ProClient;
    double NnfField;
    int32_t TransactionId;
    char PAN[10];
    int32_t AlgoID;
    short Reserved_0;
    char Reserved_1[32];
};


/**
 * OrderEntry Core
 */

class OrderEntry
{
  public:
    void operationPull(ap_uint<32> &regRxOperation,
                       hls::stream<orderEntryOperationPack_t> &operationStreamPack,
                       hls::stream<orderEntryOperationPack_t> &operationHostStreamPack,
                       hls::stream<orderEntryOperation_t> &operationStream
                     );

    void operationEncode(hls::stream<orderEntryOperation_t> &operationStream,
                         hls::stream<orderEntryOperationEncode_t> &operationEncodeStream);

    void openListenPortTcp(hls::stream<ipTcpListenPortPack_t> &listenPortStream,
                           hls::stream<ipTcpListenStatusPack_t> &listenStatusStream);

    void openActivePortTcp(ap_uint<32> &regControl,
                           ap_uint<32> &regDestAddress,
                           ap_uint<32> &regDestPort,
                           ap_uint<32> &regDebug,
                           hls::stream<ipTuplePack_t> &openConnectionStream,
                           hls::stream<ipTcpConnectionStatusPack_t> &connectionStatusStream,
                           hls::stream<ipTcpCloseConnectionPack_t> &closeConnectionStream,
                           hls::stream<ipTcpTxStatusPack_t> &txStatusStream,
                           hls::stream<ap_uint<64>> &boxIPPortFIFO,
                           hls::stream<bool> &sendBoxFIFO,
                           ap_uint<64> &GRResponseCapture);

    void notificationHandlerTcp(ap_uint<32> &regNotification,
                                ap_uint<32> &regReadRequest,
                                hls::stream<ipTcpNotificationPack_t> &notificationStream,
                                hls::stream<ipTcpReadRequestPack_t> &readRequestStream);

    void serverProcessTcp(ap_uint<32> &regRxData,
                          ap_uint<32> &regRxMeta,
                          ap_uint<64> &GRResponse,
                          ap_uint<64> &serverProcessState,
                          hls::stream<ipTcpRxMetaPack_t> &rxMetaStream,
                          hls::stream<ipTcpRxDataPack_t> &rxDataStream,
                          hls::stream<ap_uint<64>> &sessKeyFIFO,
                          hls::stream<ap_uint<64>> &boxIPPortFIFO);
                        //   hls::stream<bool> &sendMSFIFO);

     void checksumGenerate(ap_uint<32> &regControl,
                          hls::stream<orderEntryOperationEncode_tt> &operationEncodeStream,
                          hls::stream<orderEntryOperationEncode_tt> &operationEncodeStreamRelay,
                          hls::stream<sumOperation_t> &sumOperationStream);

    void operationProcessTcp(ap_uint<32> &regCaptureControl,
                             ap_uint<32> &regProcessOperation,
                             ap_uint<32> &regTxOrder,
                             ap_uint<32> &regTxData,
                             ap_uint<32> &regTxMeta,
                             ap_uint<32> &regTxStatus,
                             ap_uint<32> &regTxDrop,
                             ap_uint<1024> &regCaptureBuffer,
                             ap_uint<32>&regTraderId,
                             ap_uint<32>&regBranchID,
                             ap_uint<32>&regBoxID,
                             ap_uint<32>&regPass1,
                             ap_uint<32>&regPass2,
                             ap_uint<64> &operationProcessState,
                             hls::stream<orderEntryOperationEncode_tt> &operationEncodeStream,
                             hls::stream<sumOperation_t> &sumOperationStream,
                             hls::stream<ipTcpTxMetaPack_t> &txMetaStream,
                             hls::stream<ipTcpTxDataPack_t> &txDataStream,
                             hls::stream<ap_uint<64>> &sessKeyFIFO,
                             hls::stream<bool> &sendBoxFIFO);
                          //  hls::stream<bool> &sendMSFIFO);
               
    void byterev16(ap_uint<16>&variable);
    void byterev32(ap_uint<32>&variable);
    // void byterev64(ap_uint<64>&variable);
   
    
    void eventHandler(ap_uint<32> &regRxEvent, hls::stream<clockTickGeneratorEvent_t> &eventStream);

  private:
    connectionStatus_t mConnectionStatus;
    // unsigned char sessKey[8];

    // we store a template for the egress message here and populate the dynamic
    // fields such as price and quantity before we transmit, the partial sum
    // for the template message is pre-computed, a potential improvement for
    // reduced manual maintenance would be to calculate at compile time
    ap_uint<16> messageTemplateSum = 0x1b65;

    // clang-format off
    ap_uint<64> messageTemplate[OE_MSG_NUM_FRAME] =
    {
        0x383d4649582e342e,
        0x325e393d3133355e,
        0x33353d445e33343d,
        0x0000000000000000, // sequence (MSB)
        0x00005e34393d4142, // sequence (LSB)
        0x433132334e5e3530,
        0x3d58465f46494e54,
        0x4543485e35323d32,
        0x303139303832382d,
        0x0000000000000000, // timestamp
        0x5e35363d434d455e,
        0x35373d475e313432,
        0x3d49455e5e33353d,
        0x445e313d584c4e58,
        0x3132333435363738,
        0x5e31313d00000000, // orderId (MSB)
        0x0000000000005e33, // orderId (LSB)
        0x383d000000000000, // quantity (MSB)
        0x000000005e34303d, // quantity (LSB)
        0x325e34343d000000, // price (MSB)
        0x000000000000005e, // price (LSB)
        0x35343d315e35353d,
        0x584c4e585e36303d,
        0x3230313930383238,
        0x2d31303a31313a31,
        0x325e313032383d4e,
        0x5e3130373d43455a,
        0x392043393337355e,
        0x3230343d305e3937,
        0x30323d315e5e3130,
        0x3d43484b2e2e2e2e,
        0x2e2e2e2e2e2e2e2e,
    };
    // clang-format on

    ap_uint<64> byteReverse(ap_uint<64> inputData);

    ap_uint<80> uint32ToAscii(ap_uint<32> inputData);

    void bcdDigitiser(ap_uint<1> &carryIn, ap_uint<4> &bcdDigit, ap_uint<4> &bcdNext, ap_uint<1> &carryOut);
    
};


#endif

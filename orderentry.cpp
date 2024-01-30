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



#include <iostream>
#include "orderentry.hpp"
void OrderEntry::byterev16(ap_uint<16>&variable)
{
    ap_uint<16>num=(variable);
    variable=0;
    variable.range(7,0)=num.range(15,8);
    variable.range(15,8)=num.range(7,0);
}
void OrderEntry::byterev32(ap_uint<32> &variable)
{
    ap_uint<32> num = (variable);
    variable = 0;
    variable.range(7, 0) = num.range(31, 24);
    variable.range(15, 8) = num.range(23, 16);
    variable.range(23, 16) = num.range(15, 8);
    variable.range(31, 24) = num.range(7, 0);
}


#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */

static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
 * Bit-manipulation functions defined by the MD5 algorithm
 */

#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

uint32_t rotateLeft(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}
void md5Init(MD5Context *ctx)
{
#pragma HLS inline off
    ctx->size = (uint64_t)0;

    ctx->buffer[0] = (uint32_t)A;
    ctx->buffer[1] = (uint32_t)B;
    ctx->buffer[2] = (uint32_t)C;
    ctx->buffer[3] = (uint32_t)D;
}
void md5Update(MD5Context *ctx, uint8_t *input_buffer, size_t input_len)
{
#pragma HLS inline off
    uint32_t input[16];
    unsigned int offset = ctx->size % 64;
    ctx->size += (uint64_t)input_len;

    // Copy each byte in input_buffer into the next space in our context input
    for (unsigned int i = 0; i < input_len; ++i)
    {
        ctx->input[offset++] = (uint8_t) * (input_buffer + i);

        // If we've filled our context input, copy it into our local array input
        // then reset the offset to 0 and fill in a new buffer.
        // Every time we fill out a chunk, we run it through the algorithm
        // to enable some back and forth between cpu and i/o
        if (offset % 64 == 0)
        {
            for (unsigned int j = 0; j < 16; ++j)
            {
                // Convert to little-endian
                // The local variable `input` our 512-bit chunk separated into 32-bit words
                // we can use in calculations
                input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                           (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                           (uint32_t)(ctx->input[(j * 4) + 1]) << 8 |
                           (uint32_t)(ctx->input[(j * 4)]);
            }
            md5Step(ctx->buffer, input);
            offset = 0;
        }
    }
}
void md5Finalize(MD5Context *ctx)
{
#pragma HLS inline off
    uint32_t input[16];
    unsigned int offset = ctx->size % 64;
    unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

    // Fill in the padding andndo the changes to size that resulted from the update
    md5Update(ctx, PADDING, padding_length);
    ctx->size -= (uint64_t)padding_length;

    // Do a final update (internal to this function)
    // Last two 32-bit words are the two halves of the size (converted from bytes to bits)
    for (unsigned int j = 0; j < 14; ++j)
    {
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->input[(j * 4) + 1]) << 8 |
                   (uint32_t)(ctx->input[(j * 4)]);
    }
    input[14] = (uint32_t)(ctx->size * 8);
    input[15] = (uint32_t)((ctx->size * 8) >> 32);

    md5Step(ctx->buffer, input);

    // Move the result into digest (convert from little-endian)
    for (unsigned int i = 0; i < 4; ++i)
    {
        ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
        ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >> 8);
        ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
        ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
    }
}

void md5Step(uint32_t *buffer, uint32_t *input)
{
#pragma HLS inline off
    uint32_t AA = buffer[0];
    uint32_t BB = buffer[1];
    uint32_t CC = buffer[2];
    uint32_t DD = buffer[3];

    uint32_t E;

    unsigned int j;

    for (unsigned int i = 0; i < 64; ++i)
    {
        switch (i / 16)
        {
        case 0:
            E = F(BB, CC, DD);
            j = i;
            break;
        case 1:
            E = G(BB, CC, DD);
            j = ((i * 5) + 1) % 16;
            break;
        case 2:
            E = H(BB, CC, DD);
            j = ((i * 3) + 5) % 16;
            break;
        default:
            E = I(BB, CC, DD);
            j = (i * 7) % 16;
            break;
        }

        uint32_t temp = DD;
        DD = CC;
        CC = BB;
        BB = BB + rotateLeft(AA + E + K[i] + input[j], S[i]);
        AA = temp;
    }

    buffer[0] += AA;
    buffer[1] += BB;
    buffer[2] += CC;
    buffer[3] += DD;
}

void md5String(unsigned char *input, unsigned char *output, int length)
{
#pragma HLS inline off
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, input, length);
    md5Finalize(&ctx);

    // uint8_t *result = malloc(16);
    // memcpy(result, ctx.digest, 16);
    for (int i = 0; i < 16; i++)
        output[i] = ctx.digest[i];
    // return result;
}

/**
 * OrderEntry Core
 */

void OrderEntry:: operationPull(ap_uint<32> &regRxOperation,
                               hls::stream<orderEntryOperationPack_t> &operationStreamPack,
                               hls::stream<orderEntryOperationPack_t> &operationHostStreamPack,
                   hls::stream<orderEntryOperation_t> &operationStream
                   
                              )
{
#pragma HLS PIPELINE II = 1 style = flp

    // char *str1 = "vaibhav";
    // md5String(str1,7);
    mmInterface intf;
    orderEntryOperationPack_t operationPack;
    orderEntryOperation_t operation ;
   
    

                                         
    static ap_uint<32> countRxOperation = 0;

    // priority to direct path from PricingEngine then host offload path
    // TODO: add register control to enable/disable these different paths?
    if (operationStreamPack.empty())
    {
        operationPack = operationStreamPack.read();
        ++countRxOperation;
        intf.orderEntryOperationUnpack(&operationPack, &operation);
        operationStream.write(operation);
    }
    
    else if (!operationHostStreamPack.empty())
    {
        operationPack = operationHostStreamPack.read();
        ++countRxOperation;
        intf.orderEntryOperationUnpack(&operationPack, &operation);
        operationStream.write(operation);
        
    }

    regRxOperation = countRxOperation;

    return;
}

void OrderEntry::operationEncode(hls::stream<orderEntryOperation_t> &operationStream,
                                 hls::stream<orderEntryOperationEncode_t> &operationEncodeStream)
{
#pragma HLS PIPELINE II = 1 style = flp

    orderEntryOperation_t operation;
    orderEntryOperationEncode_t operationEncode;
    ap_uint<80> orderIdEncode, quantityEncode, priceEncode;

    if (!operationStream.empty())
    {
        operation = operationStream.read();

        orderIdEncode = uint32ToAscii(operation.orderId);
        quantityEncode = uint32ToAscii(operation.quantity);
        priceEncode = uint32ToAscii(operation.price);

        operationEncode.timestamp = operation.timestamp;
        operationEncode.opCode = operation.opCode;
        operationEncode.symbolIndex = operation.symbolIndex;
        operationEncode.orderId = orderIdEncode;
        operationEncode.quantity = quantityEncode;
        operationEncode.price = priceEncode;
        operationEncode.direction = operation.direction;

        operationEncodeStream.write(operationEncode);
    }

    return;
}

void OrderEntry::openListenPortTcp(hls::stream<ipTcpListenPortPack_t> &listenPortStream,
                                   hls::stream<ipTcpListenStatusPack_t> &listenStatusStream)
{
#pragma HLS PIPELINE II = 1 style = flp

    ipTcpListenPortPack_t listenPortPack;
    ipTcpListenStatusPack_t listenStatusPack;
    bool listenDone = false;

    static ap_uint<2> state = 0;
#pragma HLS RESET variable = state

    switch (state)
    {
    case 0:
    {
        // TODO: remove hard coded listen port
        listenPortPack.data = 7;
        listenPortPack.keep = 0x3;
        listenPortPack.last = 1;
        listenPortStream.write(listenPortPack);
        state = 1;
        break;
    }
    case 1:
    {
        if (!listenStatusStream.empty())
        {
            listenStatusPack = listenStatusStream.read();
            if (1 == listenStatusPack.data)
            {
                state = 2;
            }
            else
            {
                state = 0;
            }
        }
        break;
    }
    case 2:
    {
        // IDLE
        break;
    }
    } // switch
}


void OrderEntry::openActivePortTcp(ap_uint<32> &regControl,
                                   ap_uint<32> &regDestAddress,
                                   ap_uint<32> &regDestPort,
                                   ap_uint<32> &regDebug,
                                   hls::stream<ipTuplePack_t> &openConnectionStream,
                                   hls::stream<ipTcpConnectionStatusPack_t> &connectionStatusStream,
                                   hls::stream<ipTcpCloseConnectionPack_t> &closeConnectionStream,
                                   hls::stream<ipTcpTxStatusPack_t> &txStatusStream,
                                   hls::stream<ap_uint<64>> &boxIPPortFIFO,
                                   hls::stream<bool> &sendBoxFIFO,
                                   ap_uint<64> &GRResponseCapture)
{
#pragma HLS PIPELINE II = 1 style = flp

    mmInterface intf;
    ipTuple_t tuple;
    ipTuplePack_t tuplePack;
    ipTcpTxStatus_t txStatus;
    ipTcpTxStatusPack_t txStatusPack;
    ipTcpCloseConnectionPack_t closeConnectionPack;
    ipTcpConnectionStatusPack_t connectionStatusPack;

    enum stateType
    {
        IDLE,
        INIT_CON,
        WAIT_CON,
        ACTIVE_CON
    };
    static stateType state = IDLE;
    static ipTcpConnectionStatus_t connectionStatus;
    static ap_uint<1> statusConnected = 0;
    static ap_uint<16> statusLength = 0;
    static ap_uint<30> statusSpace = 0;
    static ap_uint<2> statusError = 0;
    static ap_uint<16> statusSessionID = 0;

    static ap_uint<32> countDebug = 0;
    static ap_uint<32> boxIP,boxPort;
    static bool grDisconnect=false;

    if (!txStatusStream.empty())
    {
        txStatusPack = txStatusStream.read();
        intf.ipTcpTxStatusStreamUnpack(&txStatusPack, &txStatus);
        statusLength = txStatus.length;
        statusSpace = txStatus.space;
        statusError = txStatus.error;
    }

    switch (state)
    {
    case IDLE:
    {
        if (OE_TCP_CONNECT & regControl)
        {
            countDebug = (countDebug | 0x00000001);
            KDEBUG("In IDLE State");
            state = INIT_CON;
        }
        break;
    }
    case INIT_CON:
    {
        countDebug = (countDebug | 0x00000020);
        tuple.address = regDestAddress;
        tuple.port = regDestPort;
        intf.ipTuplePack(&tuple, &tuplePack);
        tuplePack.last = 1;
        tuplePack.keep = 0x3F; // to see which bytes to keep in the tuplePack sent ahead
        openConnectionStream.write(tuplePack);

        state = WAIT_CON;
        break;
    }
    case WAIT_CON:
    {
        countDebug = (countDebug | 0x00000300);
        if (!connectionStatusStream.empty())
        {
            countDebug = (countDebug | 0x00004000);
            connectionStatusPack = connectionStatusStream.read();
            intf.ipTcpConnectionStatusUnpack(&connectionStatusPack, &connectionStatus);
            if (connectionStatus.success)
            {
                countDebug = (countDebug | 0x00050000);
                state = ACTIVE_CON;
                statusConnected = 0x1;
                statusLength = 0x0;
                statusSpace = 0xffff;
                statusError = TXSTATUS_SUCCESS;
                statusSessionID = connectionStatus.sessionID;
                if(grDisconnect)//boxConnect
                {
                    KDEBUG("set sendbox to true");
                    sendBoxFIFO.write(true);
                }
            }
        }
        // This code added to allow reconnect or disconnect to get out of WAIT_CON state
        // Note 0x007 instead of 0x006 to show this path was taken.
        if (0 == (OE_TCP_CONNECT & regControl))
        {
            countDebug = (countDebug | 0x00700000);
            state = IDLE;
            statusConnected = 0x0;
            statusLength = 0x0;
            statusSpace = 0x0;
            statusError = TXSTATUS_CLOSED;
        }
        break;
    }
    case ACTIVE_CON:
    {
        countDebug = (countDebug | 0x00600000);
        if (0 == (OE_TCP_CONNECT & regControl))
        {
            KDEBUG("closed connection successfully");
            countDebug = (countDebug | 0x07000000);
            closeConnectionPack.data = connectionStatus.sessionID;
            closeConnectionPack.keep = 0x3;
            closeConnectionPack.last = 1;
            closeConnectionStream.write(closeConnectionPack);
            state = IDLE;
            statusConnected = 0x0;
            statusLength = 0x0;
            statusSpace = 0x0;
            statusError = TXSTATUS_CLOSED;
        }
        if(!boxIPPortFIFO.empty())
        {
            ap_uint<64> box = boxIPPortFIFO.read();
            boxIP = box.range(31,0);
            boxPort = box.range(63,32);
            GRResponseCapture.range(31,0)=boxIP;
            GRResponseCapture.range(63,32)=boxPort;
            grDisconnect=true;
            KDEBUG("box port received: "<<box);
            // regDestAddress=boxIP;
            // regDestPort=boxPort;
            // regDebug = boxIP;
            // state=BOX_CON_OPEN;
        }
        break;
    }
    default:
    {
        countDebug = (countDebug | 0x80000000);
        state = IDLE;
        break;
    }
    }

    // TODO: transfer via stream interface rather than use private struct member
    mConnectionStatus.connected = statusConnected;
    mConnectionStatus.length = statusLength;
    mConnectionStatus.space = statusSpace;
    mConnectionStatus.error = statusError;
    mConnectionStatus.sessionID = statusSessionID;

    // regDebug = countDebug;
}

void OrderEntry::notificationHandlerTcp(ap_uint<32> &regNotification,
                                        ap_uint<32> &regReadRequest,
                                        hls::stream<ipTcpNotificationPack_t> &notificationStream,
                                        hls::stream<ipTcpReadRequestPack_t> &readRequestStream)
{
#pragma HLS PIPELINE II = 1 style = flp

    mmInterface intf;
    ipTcpNotification_t notification;
    ipTcpNotificationPack_t notificationPack;
    ipTcpReadRequest_t readRequest;
    ipTcpReadRequestPack_t readRequestPack;

    static ap_uint<32> countNotification = 0;
    static ap_uint<32> countReadRequest = 0;

    if (!notificationStream.empty())
    {
        notificationPack = notificationStream.read();
        ++countNotification;
        intf.ipTcpNotificationUnpack(&notificationPack, &notification);
        if (notification.length != 0)
        {
            readRequest.sessionID = notification.sessionID;
            readRequest.length = notification.length;
            intf.ipTcpReadRequestPack(&readRequest, &readRequestPack);
            readRequestPack.last = 1;
            readRequestPack.keep = 0x3F;
            readRequestStream.write(readRequestPack);
            ++countReadRequest;
        }
    }

    regNotification = countNotification;
    regReadRequest = countReadRequest;
}

void OrderEntry::serverProcessTcp(ap_uint<32> &regRxData,
                                  ap_uint<32> &regRxMeta,
                                  ap_uint<64> &GRResponse,
                                  ap_uint<64> &serverProcessState,
                                  hls::stream<ipTcpRxMetaPack_t> &rxMetaStream,
                                  hls::stream<ipTcpRxDataPack_t> &rxDataStream,
                                  hls::stream<ap_uint<64>> &sessKeyFIFO,
                                  hls::stream<ap_uint<64>> &boxIPPortFIFO)
                                //   hls::stream<bool> &sendMSFIFO)
{
#pragma HLS PIPELINE II = 1 style = flp

    ipTcpRxMetaPack_t rxMetaPack;
    ap_uint<16> sessionID;
    ap_axiu<64, 0, 0, 0> currWord;
    enum stateType 
    
    {
        READ_META_GR,
        READ_DATA_GR,
        PROCESS_GR_IP,
        PROCESS_DATA_GR,
        READ_META_BOX,
        READ_DATA_BOX,
        PROCESS_DATA_BOX,
        READ_META_MS_SO,
        READ_DATA_MS_SO,
        PROCESS_DATA_MS_SO
    };
    static stateType state = READ_META_GR;

    static ap_uint<32> countRxData = 0;
    static ap_uint<32> countRxMeta = 0;
    static ap_uint<608> MS_GR_raw = 0;
    static int framecount = 0;
    static int start = 0;
    static ap_uint<16> tCode;
    static ap_uint<832> gr_resp; // 98 = data(76) + 22 bytes of data (length, seqNo, checksum)
    static ap_uint<640> box_resp;
    static ap_uint<2432> ms_so_resp;
    static ap_uint<32> ip[4];
    // static ap_uint<832> signon_resp;
    static ap_uint<8> dot = '.', current;
    serverProcessState = state;
    switch (state)
    {
    case READ_META_GR:
    {
        // MS_GR header
        if (!rxMetaStream.empty())
        {
            KDEBUG("Read META GR");
            // KDEBUG("rx meta  not empty: " << rxMetaStream.empty());
            rxMetaPack = rxMetaStream.read();
            ++countRxMeta;
            sessionID = rxMetaPack.data;
            state = READ_DATA_GR;
        }
        break;
    }
    case READ_DATA_GR:
    {

        // MS_GR data
        /*
        value = 0;
        value |= ipAddrA << 24; ap_uint<8> each
        value |= ipAddrB << 16;
        value |= ipAddrC << 8;
        value |= ipAddrD << 0;
        ip_address to send is ap_uint<32>, port as well
        */

        if (!rxDataStream.empty())
        {
            KDEBUG("Read DATA GR");
            currWord = rxDataStream.read();
            KDEBUG("debug1: "<<(char)currWord.data.range(7,0));
            // KDEBUG("serverprocesstcp1: " << currWord.data);
            KDEBUG("start: "<<start);
            gr_resp.range(start + 63, start) = currWord.data; // var.range(x+2,x) sid
            // GRResponse.range(start + 63, start) = currWord.data; // var.range(x+2,x) sid
            start += 64;
            ++countRxData;
            if (currWord.last)
            {
                state = PROCESS_GR_IP;
                start = 70;
                ip[0] = ip[1] = ip[2] = ip[3] = 0;
                framecount =0;
            }
            // KDEBUG("currword.last: "<<(bool)(currWord.last))
            // KDEBUG("current state: "<<state);
        }
        break;
    }
    case PROCESS_GR_IP:
    {   
        if(start>=86)
        {
            state=PROCESS_DATA_GR;
        }
        current = gr_resp.range(start * 8 + 7, start * 8);
        if (current != dot && current!=0)
        {
            
            ip[framecount] = ip[framecount] * 10 + (current - 48);
        }
        else
        {
            framecount++;
        }
        start++;
        break;
    }
    case PROCESS_DATA_GR:
    {           
        KDEBUG("Process DATA GR");
        tCode = gr_resp.range(23*8+15,23*8);
        byterev16(tCode);
        // regRxMeta=tCode;
        //status code checked
        // ap_uint<32> tempIP;
        // tempIP = 0;
        char sessionKey[8];
        ap_uint<32> port, ipaddr;
        ap_uint<64> portIP = 0;
        ipaddr = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];
        KDEBUG("ip address:");
        KDEBUG(ip[0]);
        KDEBUG(ip[1]);
        KDEBUG(ip[2]);
        KDEBUG(ip[3]);
        // KDEBUG(ipaddr);
        port = gr_resp.range(89 * 8 + 7, 86 * 8);
        byterev32(port);
        // KDEBUG(port);
        ap_uint<64>sessKey;
        for (int ix = 0; ix < 8; ix++){

            sessionKey[ix] = (char)gr_resp.range((90 + ix) * 8 + 7, ((90 + ix) * 8));
            sessKey.range((ix+1)*8-1,ix*8)=sessionKey[ix];
        }
        portIP.range(31,0)=ipaddr;
        portIP.range(63,32)=port;
        KDEBUG(ipaddr << "\t"<< port << "\t"<< portIP);
        boxIPPortFIFO.write(portIP);
        sessKeyFIFO.write(sessKey);
        GRResponse.range(63,32)=port;
        GRResponse.range(31,0)=ipaddr;

        // if(tCode == MS_GR_SUCCESS)
        // | Rx Data Frames             | 3232240940 |
        // | Rx Meta Frames             |  257884160
        // regRxData=ipaddr;
        // regRxMeta=port;
        // 80-83 port
        // 84-91 sessionkey
        state = READ_META_BOX;
    }
    case READ_META_BOX:
    {
        // MS_GR header
        if (!rxMetaStream.empty())
        {
            KDEBUG("Read META BOX");
            KDEBUG("rx meta  not empty: " << rxMetaStream.empty());
            rxMetaPack = rxMetaStream.read();
            ++countRxMeta;
            sessionID = rxMetaPack.data;
            state = READ_DATA_BOX;
            start=0;
        }
        break;
    }
    case READ_DATA_BOX:
    {
        // BOX data
        if (!rxDataStream.empty())
        {
            KDEBUG("Read DATA BOX"<< rxDataStream.size());
            currWord = rxDataStream.read();
            KDEBUG("BOX debug: "<<currWord.data<<"\t"<<currWord.last);
            KDEBUG("start: "<<start);
            box_resp.range(start + 63, start) = currWord.data; // var.range(x+2,x) sid
            // GRResponse.range(start + 63, start) = currWord.data; // var.range(x+2,x) sid
            start += 64;
            ++countRxData;
            if (currWord.last)
            {
                state = PROCESS_DATA_BOX;
            }
            // KDEBUG("currword.last: "<<(bool)(currWord.last))
            // KDEBUG("current state: "<<state);
        }
        break;
    }
    case PROCESS_DATA_BOX:
    {
        //23 and 24 are transaction code, 23001 for successful box
        KDEBUG("Process DATA BOX");
        // 0-21 bytes are pre header
        // 0 th byte is (0+1)*8-1,0*8
        //22nd byte
        tCode = box_resp.range(24*8-1,22*8);
        byterev16(tCode);
        // regRxMeta=tCode;
        KDEBUG("box tCode"<< tCode);
        if(tCode == BOX_SUCCESS)
        {
            // to implement ahead
        } 
        
        sessKeyFIFO.write(1);// using this to signal that the box message has been processed and MS signon should be sent.
        // sendMSFIFO.write(true);
        state=READ_META_MS_SO;
        break;
    }
    case READ_META_MS_SO:
    {
        // MS_GR header
        if (!rxMetaStream.empty())
        {
            KDEBUG("rx meta  not empty: " << rxMetaStream.empty());
            rxMetaPack = rxMetaStream.read();
            ++countRxMeta;
            sessionID = rxMetaPack.data;
            state = READ_DATA_MS_SO;
            start=0;
        }
        break;
    }
    case READ_DATA_MS_SO:
    {
        // MS_GR data
        if (!rxDataStream.empty())
        {
            currWord = rxDataStream.read();
            KDEBUG("debug1: "<<(char)currWord.data.range(7,0));
            KDEBUG("start: "<<start);
            ms_so_resp.range(start + 63, start) = currWord.data; // var.range(x+2,x) sid
            start += 64;
            ++countRxData;
            if (currWord.last)
            {
                state = PROCESS_DATA_BOX;
            }
            // KDEBUG("currword.last: "<<(bool)(currWord.last))
            // KDEBUG("current state: "<<state);
        }
        break;
    }
    case PROCESS_DATA_MS_SO:
    {
        //23 and 24 are transaction code, 23001 for successful box
        tCode = box_resp.range(23*8+15,23*8);
        byterev16(tCode);
        // regRxMeta=tCode;
        if(tCode ==2301)
        {
            // to implement ahead
        }
        // sendMSFIFO.write(true);
        break;
    }
    default:
    {
        break;
    }
    }
    
    regRxData = countRxData;
    regRxMeta = countRxMeta;
}

void OrderEntry::checksumGenerate(ap_uint<32> &regControl,
                                  hls::stream<orderEntryOperationEncode_t> &operationEncodeStream,
                                  hls::stream<orderEntryOperationEncode_t> &operationEncodeStreamRelay,
                                  hls::stream<sumOperation_t> &sumOperationStream)
{
#pragma HLS PIPELINE II = 1 style = flp

    orderEntryOperationEncode_t operationEncode;
    sumOperation_t sumOperation;
    ap_uint<24> orderIdSum, timestampSum, quantitySum, priceSum, messageSum;
    ap_uint<1> validSum = 0;

    if (!operationEncodeStream.empty())
    {
        operationEncode = operationEncodeStream.read();

        // if checksum generation is enabled we calculate the partial sum for the payload here to be indicated on the
        // TCP kernel via metadata interface, this reduces latency as TCP can begin sending in cut-through mode rather
        // than buffer the full packet in store and forward mode
        if (OE_TCP_GEN_SUM & regControl)
        {
            timestampSum = operationEncode.timestamp.range(15, 0);
            timestampSum += operationEncode.timestamp.range(31, 16);
            timestampSum = (timestampSum + (timestampSum >> 16)) & 0xFFFF;
            timestampSum += operationEncode.timestamp.range(47, 32);
            timestampSum = (timestampSum + (timestampSum >> 16)) & 0xFFFF;
            timestampSum += operationEncode.timestamp.range(63, 48);
            timestampSum = (timestampSum + (timestampSum >> 16)) & 0xFFFF;

            orderIdSum = operationEncode.orderId.range(15, 0);
            orderIdSum += operationEncode.orderId.range(31, 16);
            orderIdSum = (orderIdSum + (orderIdSum >> 16)) & 0xFFFF;
            orderIdSum += operationEncode.orderId.range(47, 32);
            orderIdSum = (orderIdSum + (orderIdSum >> 16)) & 0xFFFF;
            orderIdSum += operationEncode.orderId.range(63, 48);
            orderIdSum = (orderIdSum + (orderIdSum >> 16)) & 0xFFFF;
            orderIdSum += operationEncode.orderId.range(79, 64);
            orderIdSum = (orderIdSum + (orderIdSum >> 16)) & 0xFFFF;

            quantitySum = operationEncode.quantity.range(15, 0);
            quantitySum += operationEncode.quantity.range(31, 16);
            quantitySum = (quantitySum + (quantitySum >> 16)) & 0xFFFF;
            quantitySum += operationEncode.quantity.range(47, 32);
            quantitySum = (quantitySum + (quantitySum >> 16)) & 0xFFFF;
            quantitySum += operationEncode.quantity.range(63, 48);
            quantitySum = (quantitySum + (quantitySum >> 16)) & 0xFFFF;
            quantitySum += operationEncode.quantity.range(79, 64);
            quantitySum = (quantitySum + (quantitySum >> 16)) & 0xFFFF;

            // the price field is not 16b aligned, need to shift by one byte
            priceSum = (operationEncode.price.range(7, 0) << 8);
            priceSum += operationEncode.price.range(23, 8);
            priceSum = (priceSum + (priceSum >> 16)) & 0xFFFF;
            priceSum += operationEncode.price.range(39, 24);
            priceSum = (priceSum + (priceSum >> 16)) & 0xFFFF;
            priceSum += operationEncode.price.range(55, 40);
            priceSum = (priceSum + (priceSum >> 16)) & 0xFFFF;
            priceSum += operationEncode.price.range(71, 56);
            priceSum = (priceSum + (priceSum >> 16)) & 0xFFFF;
            priceSum += operationEncode.price.range(79, 72);
            priceSum = (priceSum + (priceSum >> 16)) & 0xFFFF;

            // merge template message partial sum with dynamic field updates
            messageSum = messageTemplateSum;
            messageSum += orderIdSum;
            messageSum = (messageSum + (messageSum >> 16)) & 0xFFFF;
            messageSum += timestampSum;
            messageSum = (messageSum + (messageSum >> 16)) & 0xFFFF;
            messageSum += orderIdSum;
            messageSum = (messageSum + (messageSum >> 16)) & 0xFFFF;
            messageSum += quantitySum;
            messageSum = (messageSum + (messageSum >> 16)) & 0xFFFF;
            messageSum += priceSum;
            messageSum = (messageSum + (messageSum >> 16)) & 0xFFFF;
            validSum = 1;
        }
        else
        {
            messageSum = 0;
            validSum = 0;
        }

        sumOperation.subSum = messageSum;
        sumOperation.validSum = validSum;
        sumOperationStream.write(sumOperation);
        operationEncodeStreamRelay.write(operationEncode);
    }
}


void OrderEntry::operationProcessTcp(ap_uint<32> &regCaptureControl,
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
                                     hls::stream<orderEntryOperationEncode_t> &operationEncodeStream,
                                     hls::stream<sumOperation_t> &sumOperationStream,
                                     hls::stream<ipTcpTxMetaPack_t> &txMetaStream,
                                     hls::stream<ipTcpTxDataPack_t> &txDataStream,
                                     hls::stream<ap_uint<64>> &sessKeyFIFO,
                                     hls::stream<bool> &sendBoxFIFO)
                                    //  hls::stream<bool> &sendMSFIFO)
{
#pragma HLS PIPELINE II = 1 style = flp

    mmInterface intf;
    orderEntryOperationEncode_t operationEncode;
    sumOperation_t sumOperation;
    ipTcpTxMeta_t txMeta;
    ipTcpTxMetaPack_t txMetaPack;
    ipTcpTxDataPack_t txDataPack;
    ap_uint<16> length;
    ap_uint<64> frameData;
    ap_uint<32> rangeIndexHigh, rangeIndexLow;

    static unsigned char md5Checksum[16];

    enum stateType
    {
        PRE_IDLE,
        IDLE,
        SEND_MS_GR_META,
        SEND_MS_GR_DATA,
        WAIT_MS_GR_DATA,
        SEND_MS_BOX_META,
        SEND_MS_BOX_DATA,
        WAIT_MS_BOX_DATA,
        SEND_MS_SO_META,
        SEND_MS_SO_DATA,
        WAIT_MS_SO_DATA,
    };
    static stateType state = PRE_IDLE;

    static ap_uint<32> frameCount = 0;
    static orderEntryMessagePack_t messagePack = {0};

    static ap_uint<32> countProcessOperation = 0;
    static ap_uint<32> countTxOrder = 0;
    static ap_uint<32> countTxData = 0;
    static ap_uint<32> countTxMeta = 0;
    static ap_uint<32> countTxDrop = 0;
    static ap_uint<32> countDebug = 0;

    static PRE_PACKET gr_req;
    static PRE_PACKET box_req;
    static PRE_PACKET signon_req;
    static MS_GR_REQUEST req1;
    static MESSAGE_HEADER header;
    static SIGNON signon;

    static ap_uint<16> boxID, branchID;
    static ap_uint<32> traderID;
    static char pass[8];

    static ap_uint<32> seqNo = 1;
    static int metaoffset = 22;
    // static unsigned char packet_bytes_send_gr[metaoffset+48];
    static unsigned char packet_bytes_send_gr[70];
    // static unsigned char packet_bytes_box[60];
    static unsigned char packet_bytes_send_box[82];
    static unsigned char packet_bytes_send_ms[298]; // 22+276(48 for header+rest request)
// #pragma HLS BIND_STORAGE variable = packet_bytes_gr type = RAM_2P impl=BRAM
#pragma HLS BIND_STORAGE variable = packet_bytes_send_gr type = RAM_2P impl = BRAM
// #pragma HLS BIND_STORAGE variable = packet_bytes_box type = RAM_2P impl=BRAM
#pragma HLS BIND_STORAGE variable = packet_bytes_send_box type = RAM_2P impl = BRAM
#pragma HLS BIND_STORAGE variable = packet_bytes_send_ms type = RAM_2P impl = BRAM

    operationProcessState = state;
    //currently emptying anything just in case we get info from the datamover
    if (!operationEncodeStream.empty())
    {
        operationEncode = operationEncodeStream.read();
    }
    if(!sumOperationStream.empty())
    {
        sumOperation = sumOperationStream.read();
    }
    KDEBUG("current state: "<<state);
    switch (state)
    {
    case PRE_IDLE:
    {
        KDEBUG("in pre idle");
        // (regPass1 !=0 || regPass2 !=0 ) && if condition to check if password is non empty/zero
        if(regBoxID != 0 && regTraderId !=0 && regBranchID !=0)// && regTraderId!=0 && regBranchID!=0
        {
            KDEBUG("now entering IDLE of operationProcess");
            boxID = regBoxID.range(15,0);
            traderID = regTraderId;
            branchID = regBranchID.range(15,0);
            pass[3]=regPass1.range(31,24);
            pass[2]=regPass1.range(23,16);
            pass[1]=regPass1.range(15,8);
            pass[0]=regPass1.range(7,0);
            pass[7]=regPass2.range(31,24);
            pass[6]=regPass2.range(23,16);
            pass[5]=regPass2.range(15,8);
            pass[4]=regPass2.range(7,0);
            state = IDLE;
        }
        break;
    }
    case IDLE: // using this IDLE state to preencode everything needed for sending logon
    {
        KDEBUG("trader ID: "<<traderID);
        KDEBUG("box ID: "<<boxID);
        KDEBUG("branch ID: "<<branchID);
        KDEBUG("regPass: "<< regPass1 << "\t" << regPass2);
        KDEBUG(pass);
        KDEBUG("endpass");
        frameCount = 0;        
        ++countProcessOperation;
        gr_req.length = PRE_LENGTH+MS_GR_LENGTH;
        gr_req.sequenceNo = 1;
        req1.BoxID = boxID;
        // req1.BoxID = 10379; // 92 child ip
        req1.BrokerID[0] = '9';
        req1.BrokerID[1] = '0';
        req1.BrokerID[2] = '2';
        req1.BrokerID[3] = '7';
        req1.BrokerID[4] = '2';
        req1.Filler[0] = 0;
        header.TransactionCode = MS_GR_TCODE;
        header.MessageLength = MS_GR_LENGTH;
        // header.TraderId = 46950;
        header.TraderId = traderID;
        header.AlphaChar[0] = ' ';
        header.AlphaChar[1] = ' ';
        header.ErrorCode = 0;
        header.LogTime = 0;
        header.Timestamp1 = 0;
        header.Timestamp = 0;
        header.Timestamp2 = 0;
        // packet bytes for checksum
        packet_bytes_send_gr[metaoffset + 1] = header.TransactionCode.range(7, 0);
        packet_bytes_send_gr[metaoffset + 0] = header.TransactionCode.range(15, 8);
        packet_bytes_send_gr[metaoffset + 5] = header.LogTime.range(7, 0);
        packet_bytes_send_gr[metaoffset + 4] = header.LogTime.range(15, 8);
        packet_bytes_send_gr[metaoffset + 3] = header.LogTime.range(23, 16);
        packet_bytes_send_gr[metaoffset + 2] = header.LogTime.range(31, 24);
        packet_bytes_send_gr[metaoffset + 6] = header.AlphaChar[0];
        packet_bytes_send_gr[metaoffset + 7] = header.AlphaChar[1];
        packet_bytes_send_gr[metaoffset + 11] = header.TraderId.range(7, 0);
        packet_bytes_send_gr[metaoffset + 10] = header.TraderId.range(15, 8);
        packet_bytes_send_gr[metaoffset + 9] = header.TraderId.range(23, 16);
        packet_bytes_send_gr[metaoffset + 8] = header.TraderId.range(31, 24);
        packet_bytes_send_gr[metaoffset + 13] = header.ErrorCode.range(7, 0);
        packet_bytes_send_gr[metaoffset + 12] = header.ErrorCode.range(15, 8);
        packet_bytes_send_gr[metaoffset + 21] = header.Timestamp.range(7, 0);
        packet_bytes_send_gr[metaoffset + 20] = header.Timestamp.range(15, 8);
        packet_bytes_send_gr[metaoffset + 19] = header.Timestamp.range(23, 16);
        packet_bytes_send_gr[metaoffset + 18] = header.Timestamp.range(31, 24);
        packet_bytes_send_gr[metaoffset + 17] = header.Timestamp.range(39, 32);
        packet_bytes_send_gr[metaoffset + 16] = header.Timestamp.range(47, 40);
        packet_bytes_send_gr[metaoffset + 15] = header.Timestamp.range(55, 48);
        packet_bytes_send_gr[metaoffset + 14] = header.Timestamp.range(63, 56);
        packet_bytes_send_gr[metaoffset + 29] = header.Timestamp1.range(7, 0);
        packet_bytes_send_gr[metaoffset + 28] = header.Timestamp1.range(15, 8);
        packet_bytes_send_gr[metaoffset + 27] = header.Timestamp1.range(23, 16);
        packet_bytes_send_gr[metaoffset + 26] = header.Timestamp1.range(31, 24);
        packet_bytes_send_gr[metaoffset + 25] = header.Timestamp1.range(39, 32);
        packet_bytes_send_gr[metaoffset + 24] = header.Timestamp1.range(47, 40);
        packet_bytes_send_gr[metaoffset + 23] = header.Timestamp1.range(55, 48);
        packet_bytes_send_gr[metaoffset + 22] = header.Timestamp1.range(63, 56);
        packet_bytes_send_gr[metaoffset + 37] = header.Timestamp2.range(7, 0);
        packet_bytes_send_gr[metaoffset + 36] = header.Timestamp2.range(15, 8);
        packet_bytes_send_gr[metaoffset + 35] = header.Timestamp2.range(23, 16);
        packet_bytes_send_gr[metaoffset + 34] = header.Timestamp2.range(31, 24);
        packet_bytes_send_gr[metaoffset + 33] = header.Timestamp2.range(39, 32);
        packet_bytes_send_gr[metaoffset + 32] = header.Timestamp2.range(47, 40);
        packet_bytes_send_gr[metaoffset + 31] = header.Timestamp2.range(55, 48);
        packet_bytes_send_gr[metaoffset + 30] = header.Timestamp2.range(63, 56);
        packet_bytes_send_gr[metaoffset + 39] = header.MessageLength.range(7, 0);
        packet_bytes_send_gr[metaoffset + 38] = header.MessageLength.range(15, 8);

        packet_bytes_send_gr[metaoffset + 41] = req1.BoxID.range(7, 0);
        packet_bytes_send_gr[metaoffset + 40] = req1.BoxID.range(15, 8);
        packet_bytes_send_gr[metaoffset + 42] = req1.BrokerID[0];
        packet_bytes_send_gr[metaoffset + 43] = req1.BrokerID[1];
        packet_bytes_send_gr[metaoffset + 44] = req1.BrokerID[2];
        packet_bytes_send_gr[metaoffset + 45] = req1.BrokerID[3];
        packet_bytes_send_gr[metaoffset + 46] = req1.BrokerID[4];
        packet_bytes_send_gr[metaoffset + 47] = req1.Filler[0];
        md5String(&packet_bytes_send_gr[metaoffset], md5Checksum, MS_GR_LENGTH);
        packet_bytes_send_gr[1] = gr_req.length.range(7, 0);
        packet_bytes_send_gr[0] = gr_req.length.range(15, 8);
        packet_bytes_send_gr[5] = gr_req.sequenceNo.range(7, 0);
        packet_bytes_send_gr[4] = gr_req.sequenceNo.range(15, 8);
        packet_bytes_send_gr[3] = gr_req.sequenceNo.range(23, 16);
        packet_bytes_send_gr[2] = gr_req.sequenceNo.range(31, 24);
       

        for (int i = 0; i < 16; i++)
        {
#pragma HLS unroll factor = 8
            packet_bytes_send_gr[i + 6] = md5Checksum[i];
        }
        /*
        for(int i=0;i<48;i++)
        {
            #pragma HLS unroll factor = 8
            packet_bytes_send_gr[i+22]=packet_bytes_send_gr[metaoffset+i];
        }
        //gr_req done till here
        */
        for (int i = 0; i < 48; i++)
        {
#pragma HLS unroll factor = 8
            packet_bytes_send_box[metaoffset + i] = packet_bytes_send_gr[metaoffset + i];
            // packet_bytes_send_ms[metaoffset + i] = packet_bytes_send_gr[metaoffset + i];
        }
        for (int i = 0; i < 40; i++)
        {
// copy only header for the ms signon
#pragma HLS unroll factor = 8
            packet_bytes_send_ms[metaoffset + i] = packet_bytes_send_gr[metaoffset + i];
        }
        header.TransactionCode = BOX_TCODE;
        header.MessageLength = BOX_LENGTH;
        packet_bytes_send_box[metaoffset + 39] = header.MessageLength.range(7, 0);
        packet_bytes_send_box[metaoffset + 38] = header.MessageLength.range(15, 8);
        packet_bytes_send_box[metaoffset + 1] = header.TransactionCode.range(7, 0);
        packet_bytes_send_box[metaoffset + 0] = header.TransactionCode.range(15, 8);
        // packet_bytes_send_gr[metaoffset+41]=req1.BoxID.range(7,0); //update if box id changes
        // packet_bytes_send_gr[metaoffset+40]=req1.BoxID.range(15,8);
        // packet_bytes_send_gr[metaoffset+42]=req1.BrokerID[0];
        // packet_bytes_send_gr[metaoffset+43]=req1.BrokerID[1];
        // packet_bytes_send_gr[metaoffset+44]=req1.BrokerID[2];
        // packet_bytes_send_gr[metaoffset+45]=req1.BrokerID[3];
        // packet_bytes_send_gr[metaoffset+46]=req1.BrokerID[4];
        // packet_bytes[48-52] reserved
        
        //end part box
        // begin signon

        //   pass[3]=regPass1.range(31,24);
        //     pass[2]=regPass1.range(23,16);
        //     pass[1]=regPass1.range(15,8);
        //     pass[0]=regPass1.range(7,0);
        //     pass[7]=regPass2.range(31,24);
        //     pass[6]=regPass2.range(23,16);
        //     pass[5]=regPass2.range(15,8);
        //     pass[4]=regPass2.range(7,0);
        signon.UserID = traderID;
        for(int i = 0; i < 8; i++)
        {
            #pragma HLS unroll
            signon.Password[i]=pass[i];
        }
        // signon.Password[0] = 'J';
        // signon.Password[1] = 'u';
        // signon.Password[2] = 'n';
        // signon.Password[3] = '@';
        // signon.Password[4] = '2';
        // signon.Password[5] = '0';
        // signon.Password[6] = '2';
        // signon.Password[7] = '3';
        signon.BranchID = branchID;
        signon.VersionNumber = 76000;
        for (int i = 0; i < 56; i++)
        {
#pragma HLS unroll factor = 4
            signon.Reserved_4[i] = '\0';
        }
        signon.ShowIndex[0] = 'T';
        // header.LogTime = 0; //not needed already present earlier
        header.TransactionCode = MS_SIGNON_TCODE;
        header.MessageLength = MS_SIGNON_LENGTH;
        signon.LastPasswordChangeDate = 0;
        for (int i = 0; i < 8; i++)
        {
#pragma HLS unroll factor = 2
            signon.NewPassword[i] = ' ';
            signon.Reserved_1[i] = '\0';
            signon.Reserved_2[i] = '\0';
        }
        signon.Reserved_3[0] = '\0';
        // signon.Reserved_4[0]=' ';
        for (int i = 0; i < 26; i++)
        {
#pragma HLS unroll factor = 2
            signon.TraderName[i] = ' ';
            signon.BrokerName[i] = ' ';
        }
        signon.BrokerID[0] = '9';
        signon.BrokerID[1] = '0';
        signon.BrokerID[2] = '2';
        signon.BrokerID[3] = '7';
        signon.BrokerID[4] = '2';
        for (int i = 0; i < 16; i++)
        {
#pragma HLS unroll factor = 2
            signon.Reserved_5[i] = '\0';
            signon.Reserved_6[i] = '\0';
            signon.Reserved_7[i] = '\0';
        }
        // signon.Batch2StartTime = 0;
        signon.SequenceNumber = 0;
        // signon.br_el_per_mkt.Reser
        signon.br_el_per_mkt.Reserved_1 = 0;
        signon.br_el_per_mkt.CallAuction_2 = 0;
        signon.br_el_per_mkt.CallAuction_1 = 0;
        signon.br_el_per_mkt.AuctionMarket = 0;
        signon.br_el_per_mkt.SpotMarket = 0;
        signon.br_el_per_mkt.OddlotMarket = 0;
        signon.br_el_per_mkt.Normal = 0;
        signon.br_el_per_mkt.PreOpen = 0;
        signon.br_el_per_mkt.Reserved_2 = 0;
        // signon.MemberType = 0;
        signon.UserType = 0;
        // signon.ClearingStatus[0] = ' ';
        signon.BrokerStatus[0] = ' ';
        // signon.HostSwitchContext[0]=' ';
        for (int i = 0; i < 7; i++)
        {
#pragma HLS unroll factor = 2
            signon.WsClassName[i] = (char)('0' + (i + 1));
        }
        signon_req.length = PRE_LENGTH+MS_SIGNON_LENGTH;
        signon_req.sequenceNo = 2;
        seqNo = 2; //static variable for sequence number
        packet_bytes_send_ms[1] = signon_req.length.range(7, 0);
        packet_bytes_send_ms[0] = signon_req.length.range(15, 8);
        packet_bytes_send_ms[5] = signon_req.sequenceNo.range(7, 0);
        packet_bytes_send_ms[4] = signon_req.sequenceNo.range(15, 8);
        packet_bytes_send_ms[3] = signon_req.sequenceNo.range(23, 16);
        packet_bytes_send_ms[2] = signon_req.sequenceNo.range(31, 24);
        packet_bytes_send_ms[metaoffset + 1] = header.TransactionCode.range(7, 0);
        packet_bytes_send_ms[metaoffset + 0] = header.TransactionCode.range(15, 8);
        packet_bytes_send_ms[metaoffset + 39] = header.MessageLength.range(7, 0);
        packet_bytes_send_ms[metaoffset + 38] = header.MessageLength.range(15, 8);
        packet_bytes_send_ms[metaoffset + 43] = signon.UserID.range(7, 0);
        packet_bytes_send_ms[metaoffset + 42] = signon.UserID.range(15, 8);
        packet_bytes_send_ms[metaoffset + 41] = signon.UserID.range(23, 16);
        packet_bytes_send_ms[metaoffset + 40] = signon.UserID.range(31, 24);
        for (int i = 0; i < 8; i++)
        {
#pragma HLS unroll factor = 2
            packet_bytes_send_ms[metaoffset + 44 + i] = signon.Reserved_1[i];
            packet_bytes_send_ms[metaoffset + 52 + i] = signon.Password[i];
            packet_bytes_send_ms[metaoffset + 60 + i] = signon.Reserved_2[i];
            packet_bytes_send_ms[metaoffset + 68 + i] = signon.NewPassword[i];
        }
        for (int i = 0; i < 26; i++)
        {
#pragma HLS unroll factor = 2
            packet_bytes_send_ms[metaoffset + 76 + i] = signon.TraderName[i];
        }
        packet_bytes_send_ms[metaoffset + 105] = 0;
        packet_bytes_send_ms[metaoffset + 104] = 0;
        packet_bytes_send_ms[metaoffset + 103] = 0;
        packet_bytes_send_ms[metaoffset + 102] = 0; // since LastPasswordChangeDate=0
        for (int i = 0; i < 5; i++)
        {
#pragma HLS unroll factor = 5
            packet_bytes_send_ms[metaoffset + 106 + i] = signon.BrokerID[i];
        }
        packet_bytes_send_ms[metaoffset + 111] = signon.Reserved_3[0];
        packet_bytes_send_ms[metaoffset + 113] = signon.BranchID.range(7, 0);
        packet_bytes_send_ms[metaoffset + 112] = signon.BranchID.range(15, 8);
        packet_bytes_send_ms[metaoffset + 117] = signon.VersionNumber.range(7, 0);
        packet_bytes_send_ms[metaoffset + 116] = signon.VersionNumber.range(15, 8);
        packet_bytes_send_ms[metaoffset + 115] = signon.VersionNumber.range(23, 16);
        packet_bytes_send_ms[metaoffset + 114] = signon.VersionNumber.range(31, 24);
        for (int i = 0; i < 56; i++)
        {
#pragma HLS unroll factor = 2
            packet_bytes_send_ms[metaoffset + 118 + i] = signon.Reserved_4[i];
        }
        packet_bytes_send_ms[metaoffset + 175] = signon.UserType.range(7, 0);
        packet_bytes_send_ms[metaoffset + 174] = signon.UserType.range(15, 8);
        packet_bytes_send_ms[metaoffset + 183] = 0;
        packet_bytes_send_ms[metaoffset + 182] = 0;
        packet_bytes_send_ms[metaoffset + 181] = 0;
        packet_bytes_send_ms[metaoffset + 180] = 0;
        packet_bytes_send_ms[metaoffset + 179] = 0;
        packet_bytes_send_ms[metaoffset + 178] = 0;
        packet_bytes_send_ms[metaoffset + 177] = 0;
        packet_bytes_send_ms[metaoffset + 176] = 0; // sequence number is 0 when sent from host, refer page 32 of NNF protocol 5.2
        for (int i = 0; i < 14; i++)
        {
#pragma HLS unroll factor = 2
            packet_bytes_send_ms[metaoffset + 184 + i] = signon.WsClassName[i];
        }
        packet_bytes_send_ms[metaoffset + 198] = signon.BrokerStatus[0];
        packet_bytes_send_ms[metaoffset + 199] = signon.ShowIndex[0];
        packet_bytes_send_ms[metaoffset + 200] = 0;
        packet_bytes_send_ms[metaoffset + 201] = 0; // broker_eligibility=0
        for (int i = 0; i < 26; i++)
        {
#pragma HLS unroll factor = 2
            packet_bytes_send_ms[metaoffset + 202 + i] = signon.BrokerName[i];
        }
        /*
        for(int i=0;i<16;i++){
            packet_bytes_send_ms[metaoffset+228+i]=signon.Reserved_5[i];
            packet_bytes_send_ms[metaoffset+244+i]=signon.Reserved_5[i];
            packet_bytes_send_ms[metaoffset+260+i]=signon.Reserved_5[i];
        }*/
        for (int i = 0; i < 48; i++)
        {
#pragma HLS unroll factor = 4
            packet_bytes_send_ms[metaoffset + 228 + i] = '\0'; // reserved
        }

        // seqNo=2;
        KDEBUG("completed IDLE")
        state = SEND_MS_GR_META;
        break;
    }
    case SEND_MS_GR_META:
    {
        txMetaPack.last = 0;
        txMetaPack.keep = 0x7F;

        // currently static as we send a fixed message size
        length = PRE_LENGTH+MS_GR_LENGTH;

        if ((mConnectionStatus.connected) && (length <= mConnectionStatus.space) &&
            (TXSTATUS_SUCCESS == mConnectionStatus.error))
        {
            // prepare metadata fields for the current send
            txMeta.validSum = 0;
            txMeta.subSum = 0x0;
            txMeta.sessionID = mConnectionStatus.sessionID;
            txMeta.length = length;

            // write to packed structure ready for transmit
            intf.ipTcpTxMetaPack(&txMeta, &txMetaPack);
            txMetaPack.last = 1;

            // write metadata to stream interface
            txMetaStream.write(txMetaPack);
            ++countTxMeta;

            state = SEND_MS_GR_DATA;
        }
        else
        {
            ++countTxDrop;
            // state = SEND_MS_GR_META;
        }

        break;
    }
    case SEND_MS_GR_DATA:
    {
        KDEBUG("send ms gr data");
        txDataPack.last = 0;
        txDataPack.strb = 0xFF;
        txDataPack.keep = 0xFF;

        // load frame from template
        if (frameCount < 8)
        {
            for (int ctr = 0; ctr < 8; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_gr[ctr + frameCount * 8];
            }
        }
        // frameData = messageTemplate[frameCount];
        // instruct tcp kernel if this is the last frame in payload
        if ((9 - 1) == frameCount) 
        {
            // for(int xy=0;xy<70;xy++)
            // {
            //     KDEBUG((int)packet_bytes_send_gr[xy]);
            // }

            txDataPack.last = 1;
            for (int ctr = 0; ctr < 6; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_gr[ctr + frameCount * 8];
            }
            frameData.range(63, 63 - 16) = 0x0;

            // message capture recorded in register map for host visibility, check if host has capture freeze
            // control enabled before updating
            if (0 == (OE_CAPTURE_FREEZE & regCaptureControl))
            {
                regCaptureBuffer = messagePack.data;
            }

            ++countTxOrder;
            state = WAIT_MS_GR_DATA;
        }
        txDataPack.data = frameData;

        // forward frame to tcp kernel
        txDataStream.write(txDataPack);
        ++countTxData;

        // add frame to message capture - can be viewed through sw
        rangeIndexLow = (frameCount * 64);
        rangeIndexHigh = (rangeIndexLow + 63);
        if (rangeIndexHigh < 1024)
        {
            // TODO: add 2048b message capture support, truncate for now
            messagePack.data.range(rangeIndexHigh, rangeIndexLow) = frameData;
        }

        ++frameCount;
        break;
    }
    case WAIT_MS_GR_DATA:
    {
        // state = WAIT_MS_BOX_DATA;
        // KDEBUG("sendBoxFIFO "<<sendBoxFIFO.size()<<"\t sessKeyFIFO "<<sessKeyFIFO.size());

        frameCount = 0;
        
        if(!sendBoxFIFO.empty() && !sessKeyFIFO.empty())
        {
            KDEBUG("send box and session key received");
            bool varv = sendBoxFIFO.read();
            ap_uint<64>sessKey = sessKeyFIFO.read();
            for (int i = 0; i < 8; i++)
                packet_bytes_send_box[metaoffset + 52 + i] = sessKey.range((1+i)*8-1,8*i); 
            md5String(&packet_bytes_send_box[metaoffset], md5Checksum, BOX_LENGTH);
            box_req.length = PRE_LENGTH+BOX_LENGTH;
            box_req.sequenceNo = 1;
            packet_bytes_send_box[1] = box_req.length.range(7, 0);
            packet_bytes_send_box[0] = box_req.length.range(15, 8);
            packet_bytes_send_box[5] = box_req.sequenceNo.range(7, 0);
            packet_bytes_send_box[4] = box_req.sequenceNo.range(15, 8);
            packet_bytes_send_box[3] = box_req.sequenceNo.range(23, 16);
            packet_bytes_send_box[2] = box_req.sequenceNo.range(31, 24);
            for (int i = 0; i < 16; i++)
            {
            #pragma HLS unroll factor = 8
                packet_bytes_send_box[i + 6] = md5Checksum[i];
            }
            state = SEND_MS_BOX_META;
        }
        break;
    }
    case SEND_MS_BOX_META:
    
    {
        txMetaPack.last = 0;
        txMetaPack.keep = 0x7F;

        // currently static as we send a fixed message size
        length = PRE_LENGTH+BOX_LENGTH;

        // read the checksum operation, check for not empty was performed in previous state

        if ((mConnectionStatus.connected) && (length <= mConnectionStatus.space) &&
            (TXSTATUS_SUCCESS == mConnectionStatus.error))
        {
            // prepare metadata fields for the current send
            txMeta.validSum = 0;
            txMeta.subSum = 0x0;
            txMeta.sessionID = mConnectionStatus.sessionID;
            txMeta.length = length;

            // write to packed structure ready for transmit
            intf.ipTcpTxMetaPack(&txMeta, &txMetaPack);
            txMetaPack.last = 1;

            // write metadata to stream interface
            txMetaStream.write(txMetaPack);
            ++countTxMeta;

            state = SEND_MS_BOX_DATA;
        }
        else
        {
            ++countTxDrop;
            // state = IDLE;
        }

        break;
    }

    case SEND_MS_BOX_DATA:
    {
        txDataPack.last = 0;
        txDataPack.strb = 0xFF;
        txDataPack.keep = 0xFF;

        // load frame from template
        if (frameCount < 10)
        {
            for (int ctr = 0; ctr < 8; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_box[ctr + frameCount * 8];
            }
        }
        // frameData = messageTemplate[frameCount];
        // instruct tcp kernel if this is the last frame in payload
        if ((11 - 1) == frameCount)
        {
            // for(int xy=0;xy<82;xy++)
            // {
            //     KDEBUG((int)packet_bytes_send_box[xy]);
            // }

            txDataPack.last = 1;
            for (int ctr = 0; ctr < 2; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_box[ctr + frameCount * 8];
            }
            frameData.range(63, 63 - 6 * 8) = 0x0;

            // message capture recorded in register map for host visibility, check if host has capture freeze
            // control enabled before updating
            if (0 == (OE_CAPTURE_FREEZE & regCaptureControl))
            {
                regCaptureBuffer = messagePack.data;
            }
            KDEBUG("sent MS Box DATA");
             KDEBUG("sent MS Box DATA+++++++++++++++++++++++");

         

            ++countTxOrder;
            state = WAIT_MS_BOX_DATA;
        }
        txDataPack.data = frameData;

        // forward frame to tcp kernel
        txDataStream.write(txDataPack);
        ++countTxData;

        // add frame to message capture - can be viewed through sw
        rangeIndexLow = (frameCount * 64);
        rangeIndexHigh = (rangeIndexLow + 63);
        if (rangeIndexHigh < 1024)
        {
            // TODO: add 2048b message capture support, truncate for now
            messagePack.data.range(rangeIndexHigh, rangeIndexLow) = frameData;
        }

        ++frameCount;
        break;
    }
    case WAIT_MS_BOX_DATA:
    {
        KDEBUG("sessKeyFIFO empty:"<<sessKeyFIFO.empty())
        if(!sessKeyFIFO.empty())
        {
            sessKeyFIFO.read();
            state=SEND_MS_SO_META;
            frameCount=0;

            
        }
         for (long long int i = 0; i < 5; ++i) {
        long long int a = i;
           }

        break;
    }
     case SEND_MS_SO_META:
    {
       
        txMetaPack.last = 0;
        txMetaPack.keep = 0x7F;

        // currently static as we send a fixed message size
        length = PRE_LENGTH+MS_SIGNON_LENGTH; //38 frames


        // read the checksum operation, check for not empty was performed in previous state

        if ((mConnectionStatus.connected) && (length <= mConnectionStatus.space) &&
            (TXSTATUS_SUCCESS == mConnectionStatus.error))
        
        {
            // prepare metadata fields for the current send
            txMeta.validSum = 0;
            txMeta.subSum = 0x0;
            txMeta.sessionID = mConnectionStatus.sessionID;
            txMeta.length = length;

            // write to packed structure ready for transmit
            intf.ipTcpTxMetaPack(&txMeta, &txMetaPack);
            txMetaPack.last = 1;

            KDEBUG("sent MS Meta");
            // write metadata to stream interface
            txMetaStream.write(txMetaPack);
            ++countTxMeta;

            state = SEND_MS_SO_DATA;
        }
        
        
        else
        {
            ++countTxDrop;
            // state = IDLE;
        }

        break;
    }
    case SEND_MS_SO_DATA:
    {
        txDataPack.last = 0;
        txDataPack.strb = 0xFF;
        txDataPack.keep = 0xFF;

        // load frame from template
        if (frameCount < 37)
        {
            for (int ctr = 0; ctr < 8; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_ms[ctr + frameCount * 8];
            }
        }
        // frameData = messageTemplate[frameCount];
        // instruct tcp kernel if this is the last frame in payload
        if ((38 - 1) == frameCount)
        {
            txDataPack.last = 1;
            for (int ctr = 0; ctr < 2; ctr++)
            {
                frameData.range(8 * (ctr + 1) - 1, 8 * ctr) = packet_bytes_send_ms[ctr + frameCount * 8];
            }
            frameData.range(63, 63 - 6 * 8) = 0x0;

            // message capture recorded in register map for host visibility, check if host has capture freeze
            // control enabled before updating
            if (0 == (OE_CAPTURE_FREEZE & regCaptureControl))
            {
                regCaptureBuffer = messagePack.data;
            }

            ++countTxOrder;
            state = WAIT_MS_SO_DATA;
            KDEBUG("sent MS Data");
        }
        txDataPack.data = frameData;

        // forward frame to tcp kernel
        txDataStream.write(txDataPack);
        ++countTxData;

        // add frame to message capture - can be viewed through sw
        rangeIndexLow = (frameCount * 64);
        rangeIndexHigh = (rangeIndexLow + 63);
        if (rangeIndexHigh < 1024)
        {
            // TODO: add 2048b message capture support, truncate for now
            messagePack.data.range(rangeIndexHigh, rangeIndexLow) = frameData;
        }

        ++frameCount;
        break;
    }
    case WAIT_MS_SO_DATA:
    {
        break;
    }
    default:
    {
        // state = IDLE;
        break;
    }
    }

    regProcessOperation = countProcessOperation;
    regTxOrder = countTxOrder;
    regTxData = countTxData;
    regTxMeta = countTxMeta;
    regTxDrop = countTxDrop;
    regTxStatus.range(31, 31) = mConnectionStatus.connected;
    regTxStatus.range(30, 29) = mConnectionStatus.error;
    regTxStatus.range(28, 0) = mConnectionStatus.space;

    return;
}

ap_uint<64> OrderEntry::byteReverse(ap_uint<64> inputData)
{
#pragma HLS PIPELINE II = 1 style = flp

    ap_uint<64> reversed = (inputData.range(7, 0),
                            inputData.range(15, 8),
                            inputData.range(23, 16),
                            inputData.range(31, 24),
                            inputData.range(39, 32),
                            inputData.range(47, 40),
                            inputData.range(55, 48),
                            inputData.range(63, 56));

    return reversed;
}

ap_uint<80> OrderEntry::uint32ToAscii(ap_uint<32> inputData)
{
#pragma HLS PIPELINE II = 1 style = flp

    ap_uint<40> bcd = 0;
    ap_uint<80> outputAscii("30303030303030303030", 16);

    ap_uint<4> bcdDigit[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ap_uint<4> bcdNext[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ap_uint<1> carryIn[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ap_uint<1> carryOut[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#pragma HLS ARRAY_PARTITION variable = bcdDigit complete
#pragma HLS ARRAY_PARTITION variable = bcdNext complete
#pragma HLS ARRAY_PARTITION variable = carryIn complete
#pragma HLS ARRAY_PARTITION variable = carryOut complete

    // TODO: comment required to explain the algorithm but technique is from "XAPP029 - Serial Code Conversion between
    // BCD and Binary"

loop_bcd:
    for (int i = 0; i < 32; i++)
    {
        carryIn[0] = inputData.range(31 - i, 31 - i);

    loop_carry:
        for (int j = 1; j < 10; j++)
        {
            carryIn[j] = carryOut[j - 1];
        }

    loop_digit:
        for (int j = 0; j < 10; j++)
        {
            bcdDigitiser(carryIn[j], bcdDigit[j], bcdNext[j], carryOut[j]);
        }
    }

loop_ascii:
    for (int i = 0; i < 40; i += 4)
    {
        outputAscii.range(((i << 1) + 3), (i << 1)) = bcdDigit[i >> 2];
    }

    return outputAscii;
}

void OrderEntry::bcdDigitiser(ap_uint<1> &carryIn, ap_uint<4> &bcdDigit, ap_uint<4> &bcdNext, ap_uint<1> &carryOut)
{
#pragma HLS INLINE

    bcdDigit = (bcdNext << 1) | carryIn;

    switch (bcdDigit)
    {
    case 5:
        bcdNext = 0;
        carryOut = 1;
        break;
    case 6:
        bcdNext = 1;
        carryOut = 1;
        break;
    case 7:
        bcdNext = 2;
        carryOut = 1;
        break;
    case 8:
        bcdNext = 3;
        carryOut = 1;
        break;
    case 9:
        bcdNext = 4;
        carryOut = 1;
        break;
    default:
        bcdNext = bcdDigit;
        carryOut = 0;
    }

    return;
}

void OrderEntry::eventHandler(ap_uint<32> &regRxEvent , hls::stream <clockTickGeneratorEvent_t>&eventStream)
{
    #pragma HLS PIPELINE II =1 style =flp
    clockTickGeneratorEvent_t tickEvent;
    static ap_uint<32> countRxEvent=0;
    if(!eventStream.empty())
    {
        tickEvent = eventStream.read();
        ++countRxEvent;
    }
    regRxEvent=countRxEvent;
    return;
}
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

#include "orderentry_kernels.hpp"

extern "C" void orderEntryTcpTop(orderEntryRegControl_t &regControl,
                                 orderEntryRegStatus_t &regStatus,
                                 ap_uint<1024> &regCapture,
                                 ap_uint<64> &GRResponseCapture,
                                 ap_uint<64> &GRResponse,
                                 ap_uint<64> &serverProcessState,
                                 ap_uint<64> &operationProcessState,
                                 orderFields_t &regFields,
                                 hls::stream<orderEntryOperationPack_t> &operationStreamPack,
                                 hls::stream<orderEntryOperationPack_t> &operationHostStreamPack,
                                 hls::stream<ipTcpListenPortPack_t> &listenPortStreamPack,
                                 hls::stream<ipTcpListenStatusPack_t> &listenStatusStreamPack,
                                 hls::stream<ipTcpNotificationPack_t> &notificationStreamPack,
                                 hls::stream<ipTcpReadRequestPack_t> &readRequestStreamPack,
                                 hls::stream<ipTcpRxMetaPack_t> &rxMetaStreamPack,
                                 hls::stream<ipTcpRxDataPack_t> &rxDataStreamPack,
                                 hls::stream<ipTuplePack_t> &openConnectionStreamPack,
                                 hls::stream<ipTcpConnectionStatusPack_t> &connectionStatusStreamPack,
                                 hls::stream<ipTcpCloseConnectionPack_t> &closeConnectionStreamPack,
                                 hls::stream<ipTcpTxMetaPack_t> &txMetaStreamPack,
                                 hls::stream<ipTcpTxDataPack_t> &txDataStreamPack,
                                 hls::stream<ipTcpTxStatusPack_t> &txStatusStreamPack,
                                 hls::stream<clockTickGeneratorEvent_t> &eventStream
                                 )
{
// offsets could be assigned automatically, manual assignment combined with reserved struct fields can provide future
// proofing and help minimise software churn with the understanding offsets may need adjustment if structs are extended
// https://docs.xilinx.com/r/en-US/ug1399-vitis-hls/HLS-Pragmas
// https://docs.xilinx.com/r/en-US/ug1393-vitis-application-acceleration/Getting-Started-with-Vitis

#pragma HLS INTERFACE s_axilite port = regControl offset = 0x010
#pragma HLS INTERFACE s_axilite port = regStatus offset = 0x050
#pragma HLS INTERFACE s_axilite port = regCapture offset = 0x138
#pragma HLS INTERFACE s_axilite port = GRResponseCapture offset = 0x240
#pragma HLS INTERFACE s_axilite port = GRResponse
#pragma HLS INTERFACE s_axilite port = serverProcessState
#pragma HLS INTERFACE s_axilite port = operationProcessState
#pragma HLS INTERFACE s_axilite port = regFields
#pragma HLS INTERFACE ap_none port = regControl
#pragma HLS INTERFACE ap_none port = regStatus
#pragma HLS INTERFACE ap_none port = regCapture
#pragma HLS INTERFACE ap_none port = GRResponseCapture
#pragma HLS INTERFACE ap_none port = GRResponse
#pragma HLS INTERFACE ap_none port = serverProcessState
#pragma HLS INTERFACE ap_none port = operationProcessState
#pragma HLS INTERFACE ap_none port = regFields
#pragma HLS INTERFACE axis port = operationStreamPack//removed
#pragma HLS INTERFACE axis port = operationHostStreamPack//removed
#pragma HLS INTERFACE axis port = listenPortStreamPack
#pragma HLS INTERFACE axis port = listenStatusStreamPack
#pragma HLS INTERFACE axis port = notificationStreamPack
#pragma HLS INTERFACE axis port = readRequestStreamPack
#pragma HLS INTERFACE axis port = rxMetaStreamPack
#pragma HLS INTERFACE axis port = rxDataStreamPack depth = 64
#pragma HLS INTERFACE axis port = openConnectionStreamPack
#pragma HLS INTERFACE axis port = connectionStatusStreamPack
#pragma HLS INTERFACE axis port = closeConnectionStreamPack
#pragma HLS INTERFACE axis port = txMetaStreamPack
// increase from default FIFO depth to handle pushback from TCP kernel
#pragma HLS INTERFACE axis port = txDataStreamPack depth = 64
#pragma HLS INTERFACE axis port = txStatusStreamPack
#pragma HLS INTERFACE axis port = eventStream
#pragma HLS INTERFACE ap_ctrl_none port = return

    static hls::stream<orderEntryOperation_t> operationStreamFIFO;
    static hls::stream<orderEntryOperationEncode_t> operationEncodeStreamFIFO;
    static hls::stream<orderEntryOperationEncode_t> operationEncodeStreamRelayFIFO;
    static hls::stream<sumOperation_t> sumOperationStreamFIFO;
    static hls::stream<ipTcpTxStatus_t> txStatusStreamFIFO;
    static hls::stream<ap_uint<64>> boxIPPortFIFO;
    static hls::stream<ap_uint<64>> sessKeyFIFO;
    static hls::stream<bool> sendBoxFIFO;
    //static hls::stream<bool> sendMSFIFO;
    static OrderEntry kernel;

#pragma HLS stream variable = sessKeyFIFO depth = 4
#pragma HLS stream variable = boxIPPortFIFO depth = 4
#pragma HLS stream variable = sendBoxFIFO depth = 4


#pragma HLS DISAGGREGATE variable = regControl
#pragma HLS DISAGGREGATE variable = regStatus
#pragma HLS DISAGGREGATE variable = regFields
#pragma HLS DATAFLOW disable_start_propagation


    kernel.openListenPortTcp(listenPortStreamPack, listenStatusStreamPack);

    kernel.openActivePortTcp(regControl.control,
                             regControl.destAddress,
                             regControl.destPort,
                             regStatus.debug,
                             openConnectionStreamPack,
                             connectionStatusStreamPack,
                             closeConnectionStreamPack,
                             txStatusStreamPack,
                             boxIPPortFIFO,
                             sendBoxFIFO,
                        GRResponseCapture);

    kernel.operationPull(regStatus.rxOperation, operationStreamPack, operationHostStreamPack, operationStreamFIFO);

    
    kernel.operationEncode(operationStreamFIFO, operationEncodeStreamFIFO);
    
   
    kernel.checksumGenerate(
        regControl.control, operationEncodeStreamFIFO, operationEncodeStreamRelayFIFO, sumOperationStreamFIFO);
 

    kernel.operationProcessTcp(regControl.capture, // tx kernel
                               regStatus.processOperation,
                               regStatus.txOrder,
                               regStatus.txData,
                               regStatus.txMeta,
                               regStatus.txStatus,
                               regStatus.txDrop,
                               regCapture,
                               regFields.TraderId,
                               regFields.branchID,
                               regFields.boxID,
                               regFields.pass1,
                               regFields.pass2,
                               operationProcessState,
                               operationEncodeStreamRelayFIFO,
                               sumOperationStreamFIFO,
                               txMetaStreamPack,
                               txDataStreamPack,
                               sessKeyFIFO,
                               sendBoxFIFO);

    kernel.serverProcessTcp(regStatus.rxData, regStatus.rxMeta, GRResponse,serverProcessState, rxMetaStreamPack, rxDataStreamPack,sessKeyFIFO, boxIPPortFIFO);
  
    kernel.notificationHandlerTcp(
      regStatus.notification, regStatus.readRequest, notificationStreamPack, readRequestStreamPack);

    kernel.eventHandler(regStatus.rxEvent, eventStream);
}

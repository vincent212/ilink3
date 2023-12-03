/*

THIS SOFTWARE IS OPEN SOURCE UNDER THE MIT LICENSE

Copyright 2022 Vincent Maciejewski, Quant Enterprises & M2 Tech
Contact:
v@m2te.ch
mayeski@gmail.com
https://www.linkedin.com/in/vmayeski/
http://m2te.ch/


Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

https://opensource.org/licenses/MIT

*/


#pragma once

#include "polonaise/logger/act/Logger.hpp"
#include "polonaise/logger/msg/CMEAudit.hpp"

//
// https://www.cmegroup.com/confluence/display/EPICSANDBOX/iLink+3+-+Minimum+Acceptable+Audit+Trail+Elements+-+Data+Definitions+and+Validation+Rules
//

namespace m2::ilink
{

    static const std::string FROM_CME = "FROM CME";
    static const std::string TO_CME = "TO CME";

    enum class Audit
    {
        SendingTimestamps,
        MessageDirection,
        OperatorID,
        SessionID,
        ManualOrderIndicator,
        MessageType,
        Instrument,
        OrderFlowID,
        CMEGlobexOrderID,
        ClientOrderID,
        OrderRequestID,
        BuySellIndicator,
        Quantity,
        LimitPrice,
        StopPrice,
        OrderType,
        OrderQualifier,
        IFMFlag,
        DisplayQuantity,
        MinimumQuantity,
        CountryofOrigin,
        FillPrice,
        FillQuantity,
        CumulativeQuantity,
        RemainingQuantity,
        AggressorFlag,
        SourceofCancellation,
        RejectReason,
        CMEGlobexMessageID,
        CrossID,
        QuoteRequestID,
        MessageQuoteID,
        QuoteSetID,
        QuoteEntryID,
        BidPrice,
        BidSize,
        OfferPrice,
        OfferSize,
        ProcessedEntries,
        PartyDetailsListRequestID,
        ListUpdateAction,
        SelfMatchingPreventionID,
        SelfMatchPreventionInstr,
        CustomerTypeIndicatorCapacity,
        AvgPxGroupID,
        AveragePxInd,
        CmtaGiveUpCD,
        Origin,
        ClearingTradePriceType,
        CustomerHandlingInstr,
        ExecutingFirmID,
        AccountNumber,
        TakeUpFirm,
        TakeupAccountIdentifier,
        END
    };

    static std::vector<std::string> get_headers()
    {
        std::vector<std::string> headers = {
            "Sending Timestamps",
            "Message Direction",
            "Operator ID",
            "Session ID",
            "Manual Order Indicator",
            "Message Type",
            "Instrument",
            "Order Flow ID",
            "CME Globex Order ID",
            "Client Order ID",
            "Order Request ID",
            "Buy/Sell Indicator",
            "Quantity",
            "Limit Price",
            "Stop Price",
            "Order Type",
            "Order Qualifier",
            "IFM Flag",
            "Display Quantity",
            "Minimum Quantity",
            "Country of Origin",
            "Fill Price",
            "Fill Quantity",
            "Cumulative Quantity",
            "Remaining Quantity",
            "AggressorFlag",
            "Source of Cancellation",
            "Reject Reason",
            "CME Globex Message ID",
            "Cross ID",
            "Quote Request ID",
            "Message Quote ID",
            "Quote Set ID",
            "Quote Entry ID",
            "Bid Price",
            "Bid Size",
            "Offer Price",
            "Offer Size",
            "Processed Entries",
            "Party Details List Request ID",
            "ListUpdateAction",
            "Self-Matching Prevention ID",
            "Self-Match Prevention Instr",
            "Customer Type Indicator",
            "AvgPxGroupID",
            "Average Px Ind",
            "CmtaGiveUpCD",
            "Origin",
            "Clearing Trade Price Type",
            "Customer Handling Instr",
            "Executing Firm ID",
            "Account Number",
            "Take Up Firm",
            "Take up Account"};
        return headers;
    }

    static void send_audit_msg(const std::vector<std::any> &val_arr)
    {
        // print the audit message
    }

}

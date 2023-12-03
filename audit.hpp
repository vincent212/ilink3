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

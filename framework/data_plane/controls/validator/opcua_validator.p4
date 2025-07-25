/* -*- P4_16 -*- */
#ifndef __CONTROLS_OPCUA_VALIDATOR__
#define __CONTROLS_OPCUA_VALIDATOR__

#include <core.p4>
#include <tna.p4>

#include "../../types.p4"

const bit<8> OPCUA_FLAG_NONE = 0x00;
const bit<8> OPCUA_FLAG_DISABLE_LOW_SECURITY = 0x01;
const bit<8> OPCUA_FLAG_DISABLE_MEDIUM_SECURITY = 0x02;
const bit<8> OPCUA_FLAG_DISABLE_DEPRACATED_SECURITY = 0x03;

control OPCUAValidatorControl(
    inout egress_headers_t headers,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t intr_meta,
    in egress_intrinsic_metadata_from_parser_t parser_meta,
    inout egress_intrinsic_metadata_for_deparser_t deparser_meta,
    inout egress_intrinsic_metadata_for_output_port_t output_port_meta) {

    action set_flags(bit<8> validator_mask, bit<8> protocol_validator_mask) {
        meta.validator_mask = meta.validator_mask | validator_mask;
        meta.protocol_validator_mask = meta.protocol_validator_mask | protocol_validator_mask;
    }

    action drop() {
        deparser_meta.drop_ctl = 1;
        exit;
    }

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash;
    bit<32> security_policy_uri_id;

    table opcua_security_policy_uris {
        key = {
            security_policy_uri_id: exact;
        }
        actions = {
            set_flags;
            @defaultonly drop;
        }
        size = 6;
        const default_action = drop();
        const entries = {
            0xa4df2010: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_DISABLE_MEDIUM_SECURITY); // http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
            0x150c83ae: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_NONE); // http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss (High Security)
            0xa03691d5: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_DISABLE_DEPRACATED_SECURITY | OPCUA_FLAG_DISABLE_MEDIUM_SECURITY); // http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15 (Depracated) (Medium Security)
            0x91ab8be0: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_DISABLE_DEPRACATED_SECURITY | OPCUA_FLAG_DISABLE_MEDIUM_SECURITY); // http://opcfoundation.org/UA/SecurityPolicy#Basic256 (Depracated) (Medium Security)
            0xd1ed0e33: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_NONE); // http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 (High Security)
            0x7d3b6327: set_flags(VALIDATOR_FLAG_NONE, OPCUA_FLAG_DISABLE_LOW_SECURITY | OPCUA_FLAG_DISABLE_MEDIUM_SECURITY); // http://opcfoundation.org/UA/SecurityPolicy#None (Low Security)
        }
    }

    // table opcua_errors {
    //     key = {
    //         headers.opcua_error.error_id: exact;
    //     }
    //     actions = {
    //         NoAction;
    //         @defaultonly drop;
    //     }
    //     size = 256;
    //     const default_action = drop();
    //     const entries = {
    //         0x00000000: NoAction(); // Good
    //         0x00000040: NoAction(); // Uncertain
    //         0x00000080: NoAction(); // Bad
    //         0x00000180: NoAction(); // BadUnexpectedError
    //         0x00000280: NoAction(); // BadInternalError
    //         0x00000380: NoAction(); // BadOutOfMemory
    //         0x00000480: NoAction(); // BadResourceUnavailable
    //         0x00000580: NoAction(); // BadCommunicationError
    //         0x00000680: NoAction(); // BadEncodingError
    //         0x00000780: NoAction(); // BadDecodingError
    //         0x00000880: NoAction(); // BadEncodingLimitsExceeded
    //         0x0000B880: NoAction(); // BadRequestTooLarge
    //         0x0000B980: NoAction(); // BadResponseTooLarge
    //         0x00000980: NoAction(); // BadUnknownResponse
    //         0x00000A80: NoAction(); // BadTimeout
    //         0x00000B80: NoAction(); // BadServiceUnsupported
    //         0x00000C80: NoAction(); // BadShutdown
    //         0x00000D80: NoAction(); // BadServerNotConnected
    //         0x00000E80: NoAction(); // BadServerHalted
    //         0x00000F80: NoAction(); // BadNothingToDo
    //         0x00001080: NoAction(); // BadTooManyOperations
    //         0x0000DB80: NoAction(); // BadTooManyMonitoredItems
    //         0x00001180: NoAction(); // BadDataTypeIdUnknown
    //         0x00001280: NoAction(); // BadCertificateInvalid
    //         0x00001380: NoAction(); // BadSecurityChecksFailed
    //         0x00001481: NoAction(); // BadCertificatePolicyCheckFailed
    //         0x00001480: NoAction(); // BadCertificateTimeInvalid
    //         0x00001580: NoAction(); // BadCertificateIssuerTimeInvalid
    //         0x00001680: NoAction(); // BadCertificateHostNameInvalid
    //         0x00001780: NoAction(); // BadCertificateUriInvalid
    //         0x00001880: NoAction(); // BadCertificateUseNotAllowed
    //         0x00001980: NoAction(); // BadCertificateIssuerUseNotAllowed
    //         0x00001A80: NoAction(); // BadCertificateUntrusted
    //         0x00001B80: NoAction(); // BadCertificateRevocationUnknown
    //         0x00001C80: NoAction(); // BadCertificateIssuerRevocationUnknown
    //         0x00001D80: NoAction(); // BadCertificateRevoked
    //         0x00001E80: NoAction(); // BadCertificateIssuerRevoked
    //         0x00000D81: NoAction(); // BadCertificateChainIncomplete
    //         0x00001F80: NoAction(); // BadUserAccessDenied
    //         0x00002080: NoAction(); // BadIdentityTokenInvalid
    //         0x00002180: NoAction(); // BadIdentityTokenRejected
    //         0x00002280: NoAction(); // BadSecureChannelIdInvalid
    //         0x00002380: NoAction(); // BadInvalidTimestamp
    //         0x00002480: NoAction(); // BadNonceInvalid
    //         0x00002580: NoAction(); // BadSessionIdInvalid
    //         0x00002680: NoAction(); // BadSessionClosed
    //         0x00002780: NoAction(); // BadSessionNotActivated
    //         0x00002880: NoAction(); // BadSubscriptionIdInvalid
    //         0x00002A80: NoAction(); // BadRequestHeaderInvalid
    //         0x00002B80: NoAction(); // BadTimestampsToReturnInvalid
    //         0x00002C80: NoAction(); // BadRequestCancelledByClient
    //         0x0000E580: NoAction(); // BadTooManyArguments
    //         0x00000E81: NoAction(); // BadLicenseExpired
    //         0x00000F81: NoAction(); // BadLicenseLimitsExceeded
    //         0x00001081: NoAction(); // BadLicenseNotAvailable
    //         0x00002D00: NoAction(); // GoodSubscriptionTransferred
    //         0x00002E00: NoAction(); // GoodCompletesAsynchronously
    //         0x00002F00: NoAction(); // GoodOverload
    //         0x00003000: NoAction(); // GoodClamped
    //         0x00003180: NoAction(); // BadNoCommunication
    //         0x00003280: NoAction(); // BadWaitingForInitialData
    //         0x00003380: NoAction(); // BadNodeIdInvalid
    //         0x00003480: NoAction(); // BadNodeIdUnknown
    //         0x00003580: NoAction(); // BadAttributeIdInvalid
    //         0x00003680: NoAction(); // BadIndexRangeInvalid
    //         0x00003780: NoAction(); // BadIndexRangeNoData
    //         0x00003880: NoAction(); // BadDataEncodingInvalid
    //         0x00003980: NoAction(); // BadDataEncodingUnsupported
    //         0x00003A80: NoAction(); // BadNotReadable
    //         0x00003B80: NoAction(); // BadNotWritable
    //         0x00003C80: NoAction(); // BadOutOfRange
    //         0x00003D80: NoAction(); // BadNotSupported
    //         0x00003E80: NoAction(); // BadNotFound
    //         0x00003F80: NoAction(); // BadObjectDeleted
    //         0x00004080: NoAction(); // BadNotImplemented
    //         0x00004180: NoAction(); // BadMonitoringModeInvalid
    //         0x00004280: NoAction(); // BadMonitoredItemIdInvalid
    //         0x00004380: NoAction(); // BadMonitoredItemFilterInvalid
    //         0x00004480: NoAction(); // BadMonitoredItemFilterUnsupported
    //         0x00004580: NoAction(); // BadFilterNotAllowed
    //         0x00004680: NoAction(); // BadStructureMissing
    //         0x00004780: NoAction(); // BadEventFilterInvalid
    //         0x00004880: NoAction(); // BadContentFilterInvalid
    //         0x0000C180: NoAction(); // BadFilterOperatorInvalid
    //         0x0000C280: NoAction(); // BadFilterOperatorUnsupported
    //         0x0000C380: NoAction(); // BadFilterOperandCountMismatch
    //         0x00004980: NoAction(); // BadFilterOperandInvalid
    //         0x0000C480: NoAction(); // BadFilterElementInvalid
    //         0x0000C580: NoAction(); // BadFilterLiteralInvalid
    //         0x00004A80: NoAction(); // BadContinuationPointInvalid
    //         0x00004B80: NoAction(); // BadNoContinuationPoints
    //         0x00004C80: NoAction(); // BadReferenceTypeIdInvalid
    //         0x00004D80: NoAction(); // BadBrowseDirectionInvalid
    //         0x00004E80: NoAction(); // BadNodeNotInView
    //         0x00001281: NoAction(); // BadNumericOverflow
    //         0x00004F80: NoAction(); // BadServerUriInvalid
    //         0x00005080: NoAction(); // BadServerNameMissing
    //         0x00005180: NoAction(); // BadDiscoveryUrlMissing
    //         0x00005280: NoAction(); // BadSempahoreFileMissing
    //         0x00005380: NoAction(); // BadRequestTypeInvalid
    //         0x00005480: NoAction(); // BadSecurityModeRejected
    //         0x00005580: NoAction(); // BadSecurityPolicyRejected
    //         0x00005680: NoAction(); // BadTooManySessions
    //         0x00005780: NoAction(); // BadUserSignatureInvalid
    //         0x00005880: NoAction(); // BadApplicationSignatureInvalid
    //         0x00005980: NoAction(); // BadNoValidCertificates
    //         0x0000C680: NoAction(); // BadIdentityChangeNotSupported
    //         0x00005A80: NoAction(); // BadRequestCancelledByRequest
    //         0x00005B80: NoAction(); // BadParentNodeIdInvalid
    //         0x00005C80: NoAction(); // BadReferenceNotAllowed
    //         0x00005D80: NoAction(); // BadNodeIdRejected
    //         0x00005E80: NoAction(); // BadNodeIdExists
    //         0x00005F80: NoAction(); // BadNodeClassInvalid
    //         0x00006080: NoAction(); // BadBrowseNameInvalid
    //         0x00006180: NoAction(); // BadBrowseNameDuplicated
    //         0x00006280: NoAction(); // BadNodeAttributesInvalid
    //         0x00006380: NoAction(); // BadTypeDefinitionInvalid
    //         0x00006480: NoAction(); // BadSourceNodeIdInvalid
    //         0x00006580: NoAction(); // BadTargetNodeIdInvalid
    //         0x00006680: NoAction(); // BadDuplicateReferenceNotAllowed
    //         0x00006780: NoAction(); // BadInvalidSelfReference
    //         0x00006880: NoAction(); // BadReferenceLocalOnly
    //         0x00006980: NoAction(); // BadNoDeleteRights
    //         0x0000BC40: NoAction(); // UncertainReferenceNotDeleted
    //         0x00006A80: NoAction(); // BadServerIndexInvalid
    //         0x00006B80: NoAction(); // BadViewIdUnknown
    //         0x0000C980: NoAction(); // BadViewTimestampInvalid
    //         0x0000CA80: NoAction(); // BadViewParameterMismatch
    //         0x0000CB80: NoAction(); // BadViewVersionInvalid
    //         0x0000C040: NoAction(); // UncertainNotAllNodesAvailable
    //         0x0000BA00: NoAction(); // GoodResultsMayBeIncomplete
    //         0x0000C880: NoAction(); // BadNotTypeDefinition
    //         0x00006C40: NoAction(); // UncertainReferenceOutOfServer
    //         0x00006D80: NoAction(); // BadTooManyMatches
    //         0x00006E80: NoAction(); // BadQueryTooComplex
    //         0x00006F80: NoAction(); // BadNoMatch
    //         0x00007080: NoAction(); // BadMaxAgeInvalid
    //         0x0000E680: NoAction(); // BadSecurityModeInsufficient
    //         0x00007180: NoAction(); // BadHistoryOperationInvalid
    //         0x00007280: NoAction(); // BadHistoryOperationUnsupported
    //         0x0000BD80: NoAction(); // BadInvalidTimestampArgument
    //         0x00007380: NoAction(); // BadWriteNotSupported
    //         0x00007480: NoAction(); // BadTypeMismatch
    //         0x00007580: NoAction(); // BadMethodInvalid
    //         0x00007680: NoAction(); // BadArgumentsMissing
    //         0x00001181: NoAction(); // BadNotExecutable
    //         0x00007780: NoAction(); // BadTooManySubscriptions
    //         0x00007880: NoAction(); // BadTooManyPublishRequests
    //         0x00007980: NoAction(); // BadNoSubscription
    //         0x00007A80: NoAction(); // BadSequenceNumberUnknown
    //         0x00007B80: NoAction(); // BadMessageNotAvailable
    //         0x00007C80: NoAction(); // BadInsufficientClientProfile
    //         0x0000BF80: NoAction(); // BadStateNotActive
    //         0x00001581: NoAction(); // BadAlreadyExists
    //         0x00007D80: NoAction(); // BadTcpServerTooBusy
    //         0x00007E80: NoAction(); // BadTcpMessageTypeInvalid
    //         0x00007F80: NoAction(); // BadTcpSecureChannelUnknown
    //         0x00008080: NoAction(); // BadTcpMessageTooLarge
    //         0x00008180: NoAction(); // BadTcpNotEnoughResources
    //         0x00008280: NoAction(); // BadTcpInternalError
    //         0x00008380: NoAction(); // BadTcpEndpointUrlInvalid
    //         0x00008480: NoAction(); // BadRequestInterrupted
    //         0x00008580: NoAction(); // BadRequestTimeout
    //         0x00008680: NoAction(); // BadSecureChannelClosed
    //         0x00008780: NoAction(); // BadSecureChannelTokenUnknown
    //         0x00008880: NoAction(); // BadSequenceNumberInvalid
    //         0x0000BE80: NoAction(); // BadProtocolVersionUnsupported
    //         0x00008980: NoAction(); // BadConfigurationError
    //         0x00008A80: NoAction(); // BadNotConnected
    //         0x00008B80: NoAction(); // BadDeviceFailure
    //         0x00008C80: NoAction(); // BadSensorFailure
    //         0x00008D80: NoAction(); // BadOutOfService
    //         0x00008E80: NoAction(); // BadDeadbandFilterInvalid
    //         0x00008F40: NoAction(); // UncertainNoCommunicationLastUsableValue
    //         0x00009040: NoAction(); // UncertainLastUsableValue
    //         0x00009140: NoAction(); // UncertainSubstituteValue
    //         0x00009240: NoAction(); // UncertainInitialValue
    //         0x00009340: NoAction(); // UncertainSensorNotAccurate
    //         0x00009440: NoAction(); // UncertainEngineeringUnitsExceeded
    //         0x00009540: NoAction(); // UncertainSubNormal
    //         0x00009600: NoAction(); // GoodLocalOverride
    //         0x00009780: NoAction(); // BadRefreshInProgress
    //         0x00009880: NoAction(); // BadConditionAlreadyDisabled
    //         0x0000CC80: NoAction(); // BadConditionAlreadyEnabled
    //         0x00009980: NoAction(); // BadConditionDisabled
    //         0x00009A80: NoAction(); // BadEventIdUnknown
    //         0x0000BB80: NoAction(); // BadEventNotAcknowledgeable
    //         0x0000CD80: NoAction(); // BadDialogNotActive
    //         0x0000CE80: NoAction(); // BadDialogResponseInvalid
    //         0x0000CF80: NoAction(); // BadConditionBranchAlreadyAcked
    //         0x0000D080: NoAction(); // BadConditionBranchAlreadyConfirmed
    //         0x0000D180: NoAction(); // BadConditionAlreadyShelved
    //         0x0000D280: NoAction(); // BadConditionNotShelved
    //         0x0000D380: NoAction(); // BadShelvingTimeOutOfRange
    //         0x00009B80: NoAction(); // BadNoData
    //         0x0000D780: NoAction(); // BadBoundNotFound
    //         0x0000D880: NoAction(); // BadBoundNotSupported
    //         0x00009D80: NoAction(); // BadDataLost
    //         0x00009E80: NoAction(); // BadDataUnavailable
    //         0x00009F80: NoAction(); // BadEntryExists
    //         0x0000A080: NoAction(); // BadNoEntryExists
    //         0x0000A180: NoAction(); // BadTimestampNotSupported
    //         0x0000A200: NoAction(); // GoodEntryInserted
    //         0x0000A300: NoAction(); // GoodEntryReplaced
    //         0x0000A440: NoAction(); // UncertainDataSubNormal
    //         0x0000A500: NoAction(); // GoodNoData
    //         0x0000A600: NoAction(); // GoodMoreData
    //         0x0000D480: NoAction(); // BadAggregateListMismatch
    //         0x0000D580: NoAction(); // BadAggregateNotSupported
    //         0x0000D680: NoAction(); // BadAggregateInvalidInputs
    //         0x0000DA80: NoAction(); // BadAggregateConfigurationRejected
    //         0x0000D900: NoAction(); // GoodDataIgnored
    //         0x0000E480: NoAction(); // BadRequestNotAllowed
    //         0x00001381: NoAction(); // BadRequestNotComplete
    //         0x0000DC00: NoAction(); // GoodEdited
    //         0x0000DD00: NoAction(); // GoodPostActionFailed
    //         0x0000DE40: NoAction(); // UncertainDominantValueChanged
    //         0x0000E000: NoAction(); // GoodDependentValueChanged
    //         0x0000E180: NoAction(); // BadDominantValueChanged
    //         0x0000E240: NoAction(); // UncertainDependentValueChanged
    //         0x0000E380: NoAction(); // BadDependentValueChanged
    //         0x00001601: NoAction(); // GoodEdited_DependentValueChanged
    //         0x00001701: NoAction(); // GoodEdited_DominantValueChanged
    //         0x00001801: NoAction(); // GoodEdited_DominantValueChanged_DependentValueCh
    //         0x00001981: NoAction(); // BadEdited_OutOfRange
    //         0x00001A81: NoAction(); // BadInitialValue_OutOfRange
    //         0x00001B81: NoAction(); // BadOutOfRange_DominantValueChanged
    //         0x00001C81: NoAction(); // BadEdited_OutOfRange_DominantValueChanged
    //         0x00001D81: NoAction(); // BadOutOfRange_DominantValueChanged_DependentValu
    //         0x00001E81: NoAction(); // BadEdited_OutOfRange_DominantValueChanged_Depend
    //         0x0000A700: NoAction(); // GoodCommunicationEvent
    //         0x0000A800: NoAction(); // GoodShutdownEvent
    //         0x0000A900: NoAction(); // GoodCallAgain
    //         0x0000AA00: NoAction(); // GoodNonCriticalTimeout
    //         0x0000AB80: NoAction(); // BadInvalidArgument
    //         0x0000AC80: NoAction(); // BadConnectionRejected
    //         0x0000AD80: NoAction(); // BadDisconnect
    //         0x0000AE80: NoAction(); // BadConnectionClosed
    //         0x0000AF80: NoAction(); // BadInvalidState
    //         0x0000B080: NoAction(); // BadEndOfStream
    //         0x0000B180: NoAction(); // BadNoDataAvailable
    //         0x0000B280: NoAction(); // BadWaitingForResponse
    //         0x0000B380: NoAction(); // BadOperationAbandoned
    //         0x0000B480: NoAction(); // BadExpectedStreamToBlock
    //         0x0000B580: NoAction(); // BadWouldBlock
    //         0x0000B680: NoAction(); // BadSyntaxError
    //         0x0000B780: NoAction(); // BadMaxConnectionsReached
    //     }
    // }

    apply {
        // 1: Drop packets with invalid payload lengths
        bit<16> opcua_payload_length = headers.opcua.message_size.part_3 ++ headers.opcua.message_size.part_4; // Convert little endian to big endian (see opcua header)
        if (opcua_payload_length != headers.egress_meta.payload_length) {
            drop();
        }
        
        // 2: Drop packets with invalid security policies
        security_policy_uri_id = hash.get({
            headers.opcua_security_policy_uri_1.security_policy_uri,
            headers.opcua_security_policy_uri_2.security_policy_uri,
            headers.opcua_security_policy_uri_3.security_policy_uri,
            headers.opcua_security_policy_uri_4.security_policy_uri,
            headers.opcua_security_policy_uri_5.security_policy_uri,
            headers.opcua_security_policy_uri_6.security_policy_uri,
            headers.opcua_security_policy_uri_7.security_policy_uri
        });
        if (headers.opcua_security_policy_uri_1.isValid()) {
            opcua_security_policy_uris.apply();
        }

        // // 3: Drop packets with invalid error codes
        // if (headers.opcua_error.isValid()) {
        //     opcua_errors.apply();
        // }
    }

}

#endif

// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "hardhat/console.sol";

// @title CRTT
// @dev The CRTT library provides types and enums for the OpenVector Coprocessor
library CRTT {
    type DataKey is uint128;
    // these represent the key of data stored inside the data layer of coprocessor
    type EBit is uint128;
    type EUint32 is uint128;

    type RequestID is uint128;
    type ResponseID is uint128;

    enum DataType {
        SINGLE,
        UINT32,
        // is only used in store request to store a rsa public key
        RSA_PUBLIC_KEY
    }

    enum OperandLocation {
        STORAGE_KEY,
        VALUE
    }

    enum OperandEncryptionScheme {
        NONE,
        CLHSM2k,
        RSA
    }

    struct Operand {
        DataType data_type;
        OperandLocation location;
        OperandEncryptionScheme encryption_scheme;
        bytes data;
    }

    enum Operation {
        ADD,
        SUB,
        LT,
        GT,
        EQ,
        LTEQ,
        GTEQ,
        NAND
    }

    struct Request {
        Operation operation;
        Operand op1;
        Operand op2;
        // in wei
        uint256 payment;
        uint256 acceptance_callback_gas;
        uint256 submission_callback_gas;
        // The amount of wei not used in the callback won't be refunded
        // hence the callback should be as efficient and deterministic as possible
        uint256 payment_callback_gas;
        // handle all the failures in submission_callback
        // if the request is not accepted, then the submission_callback will called with the error as request is completed in processing in the coprocessor
        // in the above case acceptance_callback will not be called
        function(Response memory) external payable acceptance_callback;
        function(Response memory) external payable submission_callback;
        function(RequestID) external payable payment_callback;
    }

    enum ResponseStatus {
        ACCEPTED, // will not be used for data retrieval requests
        SUCCESS,
        FAILURE,
        INVALID_OPERATION,
        INSUFFICIENT_BALANCE,
        INVALID_DATA_TYPE,
        UNKNOWN_DATA_STORAGE_KEY,
        INVALID_ENCRYPTION_SCHEME
    }

    struct Response {
        ResponseStatus status;
        RequestID request_id;
        Operand result;
    }

    enum DataRequestedType {
        ENCRYPTED,
        REENCRYPTED,
        DECRYPTED
    }

    struct ValueOperand {
        DataType data_type;
        OperandEncryptionScheme encryption_scheme;
        bytes data;
    }

    struct DataRetrievalRequest {
        DataRequestedType requested_type;
        DataKey key;
        // in wei
        uint256 payment;
        uint256 callback_gas;
        // The amount of wei not used in the callback won't be refunded
        // hence the callback should be as efficient and deterministic as possible
        uint256 payment_callback_gas;
        function(DataRetrievalResponse memory) external payable callback;
        function(RequestID) external payable payment_callback;
        DataKey reencryption_key;
    }

    struct DataRetrievalResponse {
        ResponseStatus status;
        RequestID request_id;
        ValueOperand result;
    }

    struct DataStoreRequest {
        ValueOperand operand;
        // in wei
        uint256 payment;
        uint256 acceptance_callback_gas;
        uint256 submission_callback_gas;
        // The amount of wei not used in the callback won't be refunded
        // hence the callback should be as efficient and deterministic as possible
        uint256 payment_callback_gas;
        function(DataStoreResponse memory) external payable acceptance_callback;
        function(DataStoreResponse memory) external payable submission_callback;
        function(RequestID) external payable payment_callback;
    }

    struct DataStoreResponse {
        ResponseStatus status;
        RequestID request_id;
        DataKey result;
    }

    struct ConfidentialCoinRequest {
        bool is_mint_request;
        // sender balance is total_supply in case of mint request
        EUint32 sender_balance;
        EUint32 receiver_balance;
        // if this is not zero, then the transfer_amount will be ignored
        // the amount to be transferred in case of transfer request
        // and the amount to be minted in case of mint request
        uint256 plaintext_transfer_amount;
        bytes transfer_amount;
        // this can be used to deduct the amount from the sender balance
        // can be only be true for is_mint_request
        bool consider_amount_negative;
        // the first is owner, others can reencrypt and decrypt the data
        // it will only be considered for new data, already existing keys
        // will get their acl from existing data
        bytes[] sender_balance_storage_key_acl;
        bytes[] receiver_balance_storage_key_acl;
        // in wei
        uint256 callback_gas;
        // The amount of wei not used in the callback won't be refunded
        // hence the callback should be as efficient and deterministic as possible
        uint256 payment_callback_gas;
        function(ConfidentialCoinResponse memory) external payable callback;
        function(RequestID) external payable payment_callback;
    }

    struct ConfidentialCoinResponse {
        ResponseStatus status;
        RequestID request_id;
        // for transfer request, denotes the success of the transfer ie if sender has enough balance
        // will always be true for normal mint_request and similiar to transfer request for deduction type
        bool success;
        EUint32 sender_balance;
        EUint32 receiver_balance;
    }

    enum RequestType {
        OPERATION,
        DATA_RETRIEVAL,
        DATA_STORE,
        CONFIDENTIAL_COIN
    }

    event NewRequest(
        RequestID request_id,
        RequestType request_type,
        address sender
    );
    event RequestAccepted(RequestID request_id, address accepted_by);
    event RequestProcessed(
        RequestID request_id,
        ResponseStatus status,
        address processed_by
    );

    function isDataKeyInitialized(DataKey key) internal pure returns (bool) {
        return DataKey.unwrap(key) != 0;
    }

    function isDataKeyValid(DataKey key) internal pure returns (bool) {
        return isDataKeyInitialized(key);
    }

    function getInvalidDataKey() internal pure returns (DataKey) {
        return DataKey.wrap(0);
    }

    function dataKeyToUint128(DataKey key) internal pure returns (uint128) {
        return DataKey.unwrap(key);
    }

    function uint128ToDataKey(uint128 key) internal pure returns (DataKey) {
        return DataKey.wrap(key);
    }

    function isEUint32Initialized(EUint32 key) internal pure returns (bool) {
        return EUint32.unwrap(key) != 0;
    }

    function getUintializedEUint32() internal pure returns (EUint32) {
        return EUint32.wrap(0);
    }

    function eUint32ToUint128(EUint32 key) internal pure returns (uint128) {
        return EUint32.unwrap(key);
    }

    function eUint32ToDataKey(EUint32 key) internal pure returns (DataKey) {
        return DataKey.wrap(EUint32.unwrap(key));
    }

    function isEBitInitialized(EBit key) internal pure returns (bool) {
        return EBit.unwrap(key) != 0;
    }

    function getUintializedEBit() internal pure returns (EBit) {
        return EBit.wrap(0);
    }

    function eBitToUint128(EBit key) internal pure returns (uint128) {
        return EBit.unwrap(key);
    }

    function eBitToDataKey(EBit key) internal pure returns (DataKey) {
        return DataKey.wrap(EBit.unwrap(key));
    }

    function getDefaultRequestID() internal pure returns (RequestID) {
        return RequestID.wrap(0);
    }

    function incrementRequestID(
        RequestID request_id
    ) internal pure returns (RequestID) {
        require(
            RequestID.unwrap(request_id) < type(uint128).max,
            "Request ID overflow"
        );
        return RequestID.wrap(RequestID.unwrap(request_id) + 1);
    }

    function decrementRequestID(
        RequestID request_id
    ) internal pure returns (RequestID) {
        require(RequestID.unwrap(request_id) > 0, "Request ID underflow");
        return RequestID.wrap(RequestID.unwrap(request_id) - 1);
    }

    function requestIDToUint128(
        RequestID request_id
    ) internal pure returns (uint128) {
        return RequestID.unwrap(request_id);
    }

    function getDefaultResponseID() internal pure returns (ResponseID) {
        return ResponseID.wrap(0);
    }

    function responseIDToUint128(
        ResponseID response_id
    ) internal pure returns (uint128) {
        return ResponseID.unwrap(response_id);
    }
}

// @dev The COFHExecutor interface provides the functions to execute requests
// @notice For payment costs, the user should query the COFHExecutor contract
interface COFHExecutor {
    // @dev Execute a request
    // @param request The request to be executed
    // @return The request ID of the executed request
    // @notice This is payable beause the request may require payment
    function executeRequest(
        CRTT.Request calldata request
    ) external payable returns (CRTT.RequestID);

    // @dev Execute a data retrieval request, will retrieve data from the data layer of the coprocessor
    // a reencryption key is required if we want to reencrypt the data
    // @param request The data retrieval request to be executed
    // @return The request ID of the executed request
    // @notice This is payable beause the request may require payment
    function executeRequest(
        CRTT.DataRetrievalRequest calldata request
    ) external payable returns (CRTT.RequestID);

    // @dev Execute a data store request, will store data in the data layer of the coprocessor
    // @param request The data store request to be executed
    // @return The request ID of the executed request
    // @notice This is payable beause the request may require payment
    function executeRequest(
        CRTT.DataStoreRequest calldata request
    ) external payable returns (CRTT.RequestID);

    // @dev Execute a confidential coin request, will perform confidential coin calculation
    // namely mint and transfer
    // @param request The confidential coin request to be executed
    // @return The request ID of the executed request
    // @notice This is payable beause the request may require payment
    function executeRequest(
        CRTT.ConfidentialCoinRequest calldata request
    ) external payable returns (CRTT.RequestID);
}

// @title COFHE
// @dev The COFHE library provides support for homomorphic operations
// supported by OpenVector Coprocessor
// @notice This library is still under development and should not be used in production
library COFHE {
    address constant COFHExecutorAddress =
        0x2099B2BC946adF9203FCc9FF7Bd8306843783f6b;
    // 0x5FbDB2315678afecb367f032d93F642f64180aa3;

    // @dev Add two numbers
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function add(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Subtract two numbers
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function sub(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Check whether a is less than b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function lt(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Check whether a is greater than b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function gt(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Check whether a is equal to b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function eq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Check whether a is less than or equal to b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function lteq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Check whether a is greater than or equal to b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function gteq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Perform NAND operation on a and b
    // @param a First number
    // @param b Second number
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param completion_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the NAND operation
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function nand(
        CRTT.EBit a,
        CRTT.EBit b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEBitOperationRequest(
                CRTT.Operation.NAND,
                a,
                b,
                payment,
                acceptance_callback_gas,
                submission_callback_gas,
                payment_callback_gas,
                acceptance_callback,
                completion_callback,
                payment_callback
            );
    }

    // @dev Retrieve data from the data layer of the coprocessor
    // @param key The key of the data to be retrieved
    // @param requested_type The type of data to be retrieved
    // @param payment The amount of wei to be paid for the request
    // @param callback_gas The amount of wei to be used for the callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @param reencryption_key The id of the key to be used for reencryption
    // @return Request ID of the data retrieval request
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function retrieveData(
        CRTT.DataKey key,
        CRTT.DataRequestedType requested_type,
        uint256 payment,
        uint256 callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.DataRetrievalResponse memory) external payable callback,
        function(CRTT.RequestID) external payable payment_callback,
        CRTT.DataKey reencryption_key
    ) internal returns (CRTT.RequestID) {
        CRTT.DataRetrievalRequest memory request = CRTT.DataRetrievalRequest({
            requested_type: requested_type,
            key: key,
            payment: payment,
            callback_gas: callback_gas,
            payment_callback_gas: payment_callback_gas,
            callback: callback,
            payment_callback: payment_callback,
            reencryption_key: reencryption_key
        });
        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    // @dev Store data in the data layer of the coprocessor
    // @param operand The operand to be stored
    // @param payment The amount of wei to be paid for the request
    // @param acceptance_callback_gas The amount of wei to be used for the acceptance callback
    // @param submission_callback_gas The amount of wei to be used for the submission callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param acceptance_callback The callback function to be called after the request is accepted
    // @param submission_callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the data store request
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function sendData(
        CRTT.ValueOperand memory operand,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.DataStoreResponse memory)
            external
            payable acceptance_callback,
        function(CRTT.DataStoreResponse memory)
            external
            payable submission_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        CRTT.DataStoreRequest memory request = CRTT.DataStoreRequest({
            operand: operand,
            payment: payment,
            acceptance_callback_gas: acceptance_callback_gas,
            submission_callback_gas: submission_callback_gas,
            payment_callback_gas: payment_callback_gas,
            acceptance_callback: acceptance_callback,
            submission_callback: submission_callback,
            payment_callback: payment_callback
        });
        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    // @dev Perform confidential coin calculation
    // @param payment The amount of wei to be paid for the request
    // @param is_mint_request True if the request is a mint request, false otherwise
    // @param sender_balance The balance of the sender in case of transfer request
    // and total supply in case of mint request
    // @param receiver_balance The balance of the receiver in case of transfer request
    // and balance of the minter in case of mint request
    // @param plaintext_transfer_amount The amount to be transferred in case of transfer request
    // and the amount to be minted in case of mint request. If this is not zero,
    // then the transfer_amount will be ignored
    // @param transfer_amount The amount to be transferred in case of transfer request
    // and the amount to be minted in case of mint request
    // @param consider_amount_negative True if the amount should be deducted from the sender balance
    // in case of mint request otherwise false
    // @param sender_balance_storage_key_acl The ACL for the sender balance storage key
    // @param receiver_balance_storage_key_acl The ACL for the receiver balance storage key
    // @param callback_gas The amount of wei to be used for the callback
    // @param payment_callback_gas The amount of wei to be used for the payment callback
    // @param callback The callback function to be called after the request is processed
    // @param payment_callback The callback function to be called after the payment is processed
    // @return Request ID of the confidential coin request
    // @notice The first element of the acl list is the owner of the storage key
    // the rest of the elements can reencrypt and decrypt the data
    // @notice The sender_balance_storage_key_acl and receiver_balance_storage_key_acl
    // are only considered for mint requests
    // @notice The payment callback function should be as efficient and deterministic as possible
    // as The amount of wei not used in the callback won't be refunded
    function doConfidentialCoinCalculation(
        uint256 payment,
        bool is_mint_request,
        CRTT.EUint32 sender_balance,
        CRTT.EUint32 receiver_balance,
        uint256 plaintext_transfer_amount,
        bytes memory transfer_amount,
        bool consider_amount_negative,
        bytes[] memory sender_balance_storage_key_acl,
        bytes[] memory receiver_balance_storage_key_acl,
        uint256 callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.ConfidentialCoinResponse memory)
            external
            payable callback,
        function(CRTT.RequestID) external payable payment_callback
    ) internal returns (CRTT.RequestID) {
        CRTT.ConfidentialCoinRequest memory request = CRTT
            .ConfidentialCoinRequest({
                is_mint_request: is_mint_request,
                sender_balance: sender_balance,
                receiver_balance: receiver_balance,
                plaintext_transfer_amount: plaintext_transfer_amount,
                transfer_amount: transfer_amount,
                consider_amount_negative: consider_amount_negative,
                sender_balance_storage_key_acl: sender_balance_storage_key_acl,
                receiver_balance_storage_key_acl: receiver_balance_storage_key_acl,
                callback_gas: callback_gas,
                payment_callback_gas: payment_callback_gas,
                callback: callback,
                payment_callback: payment_callback
            });
        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    function sendEUint32OperationRequest(
        CRTT.Operation operation,
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) private returns (CRTT.RequestID) {
        CRTT.Operand memory operand1 = makeOperand(
            CRTT.OperandLocation.STORAGE_KEY,
            CRTT.OperandEncryptionScheme.CLHSM2k,
            CRTT.DataType.UINT32,
            abi.encodePacked(a)
        );
        CRTT.Operand memory operand2 = makeOperand(
            CRTT.OperandLocation.STORAGE_KEY,
            CRTT.OperandEncryptionScheme.CLHSM2k,
            CRTT.DataType.UINT32,
            abi.encodePacked(b)
        );
        CRTT.Request memory request = CRTT.Request({
            operation: operation,
            op1: operand1,
            op2: operand2,
            payment: payment,
            acceptance_callback_gas: acceptance_callback_gas,
            submission_callback_gas: submission_callback_gas,
            payment_callback_gas: payment_callback_gas,
            acceptance_callback: acceptance_callback,
            submission_callback: completion_callback,
            payment_callback: payment_callback
        });
        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    function sendEBitOperationRequest(
        CRTT.Operation operation,
        CRTT.EBit a,
        CRTT.EBit b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 submission_callback_gas,
        uint256 payment_callback_gas,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback,
        function(CRTT.RequestID) external payable payment_callback
    ) private returns (CRTT.RequestID) {
        if (operation != CRTT.Operation.NAND) {
            revert("Invalid operation for EBit");
        }

        CRTT.Operand memory operand1 = makeOperand(
            CRTT.OperandLocation.STORAGE_KEY,
            CRTT.OperandEncryptionScheme.CLHSM2k,
            CRTT.DataType.UINT32,
            abi.encodePacked(a)
        );
        CRTT.Operand memory operand2 = makeOperand(
            CRTT.OperandLocation.STORAGE_KEY,
            CRTT.OperandEncryptionScheme.CLHSM2k,
            CRTT.DataType.UINT32,
            abi.encodePacked(b)
        );
        CRTT.Request memory request = CRTT.Request({
            operation: operation,
            op1: operand1,
            op2: operand2,
            payment: payment,
            acceptance_callback_gas: acceptance_callback_gas,
            submission_callback_gas: submission_callback_gas,
            payment_callback_gas: payment_callback_gas,
            acceptance_callback: acceptance_callback,
            submission_callback: completion_callback,
            payment_callback: payment_callback
        });

        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    function makeOperand(
        CRTT.OperandLocation location,
        CRTT.OperandEncryptionScheme encryption_scheme,
        CRTT.DataType data_type,
        bytes memory data
    ) private pure returns (CRTT.Operand memory) {
        return
            CRTT.Operand({
                data_type: data_type,
                location: location,
                encryption_scheme: encryption_scheme,
                data: data
            });
    }
}

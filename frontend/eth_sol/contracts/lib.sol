// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "hardhat/console.sol";

library CRTT {
    type DataKey is uint128;
    // these represent the key of data stored inside the data layer of coprocessor
    type EBit is uint128;
    type EUint32 is uint128;

    type RequestID is uint128;
    type ResponseID is uint128;

    enum DataType {
        BIT,
        UINT32
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
        uint256 acceptance_callback_payment;
        uint256 submission_callback_gas;
        uint256 submission_callback_payment;
        // handle all the failures in submission_callback
        // if the request is not accepted, then the submission_callback will called with the error as request is completed in processing in the coprocessor
        // in the above case acceptance_callback will not be called
        function(Response memory) external payable acceptance_callback;
        // after submission_callback, recieve function may be called if eth is left, so the user contract should have a recieve function
        function(Response memory) external payable submission_callback;
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
        uint256 callback_payment;
        // after callback, recieve function may be called if eth is left, so the user contract should have a recieve function
        function(DataRetrievalResponse memory) external payable callback;
        bytes reencryption_key;
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
        uint256 acceptance_callback_payment;
        uint256 submission_callback_gas;
        uint256 submission_callback_payment;
        function(DataStoreResponse memory) external payable acceptance_callback;
        // after submission_callback, recieve function may be called if eth is left, so the user contract should have a recieve function
        function(DataStoreResponse memory) external payable submission_callback;
    }

    struct DataStoreResponse {
        ResponseStatus status;
        RequestID request_id;
        DataKey result;
    }

    enum RequestType {
        OPERATION,
        DATA_RETRIEVAL,
        DATA_STORE
    }

    event NewRequest(RequestID request_id, RequestType request_type);
    event RequestAccepted(RequestID request_id);
    event RequestProcessed(RequestID request_id, ResponseStatus status);
}

interface COFHExecutor {
    function executeRequest(
        CRTT.Request calldata request
    ) external payable returns (CRTT.RequestID);

    function executeRequest(
        CRTT.DataRetrievalRequest calldata request
    ) external payable returns (CRTT.RequestID);

    function executeRequest(
        CRTT.DataStoreRequest calldata request
    ) external payable returns (CRTT.RequestID);
}

// @title COFHE
// @dev The COFHE library provides support for homomorphic operations using COFHE scheme
// supported by OpenVector Coprocessor
// @notice This library is still under development and should not be used in production
library COFHE {
    address constant COFHExecutorAddress =
        0x5FbDB2315678afecb367f032d93F642f64180aa3;

    // @dev Add two numbers using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return Request ID of the operation
    function add(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.ADD,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Subtract two numbers using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return Request ID of the operation
    function sub(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.SUB,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Check whether a is less than b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return True if a is less than b, false otherwise
    function lt(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.LT,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Check whether a is greater than b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return True if a is greater than b, false otherwise
    function gt(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.GT,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Check whether a is equal to b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return True if a is equal to b, false otherwise
    function eq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.EQ,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Check whether a is less than or equal to b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return True if a is less than or equal to b, false otherwise
    function lteq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.LTEQ,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Check whether a is greater than or equal to b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return True if a is greater than or equal to b, false otherwise
    function gteq(
        CRTT.EUint32 a,
        CRTT.EUint32 b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEUint32OperationRequest(
                CRTT.Operation.GTEQ,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    // @dev Perform NAND operation on a and b using COFHE scheme
    // @param a First number
    // @param b Second number
    // @return Result of the NAND operation
    function nand(
        CRTT.EBit a,
        CRTT.EBit b,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
    ) internal returns (CRTT.RequestID) {
        return
            sendEBitOperationRequest(
                CRTT.Operation.NAND,
                a,
                b,
                payment,
                acceptance_callback_gas,
                acceptance_callback_payment,
                submission_callback_gas,
                submission_callback_payment,
                acceptance_callback,
                completion_callback
            );
    }

    function retrieveData(
        CRTT.DataKey key,
        CRTT.DataRequestedType requested_type,
        uint256 payment,
        uint256 callback_gas,
        uint256 callback_payment,
        function(CRTT.DataRetrievalResponse memory) external payable callback,
        bytes memory reencryption_key
    ) internal returns (CRTT.RequestID) {
        CRTT.DataRetrievalRequest memory request = CRTT.DataRetrievalRequest({
            requested_type: requested_type,
            key: key,
            payment: payment,
            callback_gas: callback_gas,
            callback_payment: callback_payment,
            callback: callback,
            reencryption_key: reencryption_key
        });
        require(
            payment <= msg.value,
            "Insufficient funds to execute the request"
        );
        return
            COFHExecutor(COFHExecutorAddress).executeRequest{value: payment}(
                request
            );
    }

    function sendData(
        CRTT.ValueOperand memory operand,
        uint256 payment,
        uint256 acceptance_callback_gas,
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.DataStoreResponse memory)
            external
            payable acceptance_callback,
        function(CRTT.DataStoreResponse memory) external payable callback
    ) internal returns (CRTT.RequestID) {
        CRTT.DataStoreRequest memory request = CRTT.DataStoreRequest({
            operand: operand,
            payment: payment,
            acceptance_callback_gas: acceptance_callback_gas,
            acceptance_callback_payment: acceptance_callback_payment,
            submission_callback_gas: submission_callback_gas,
            submission_callback_payment: submission_callback_payment,
            acceptance_callback: acceptance_callback,
            submission_callback: callback
        });
        require(
            payment <= msg.value,
            "Insufficient funds to execute the request"
        );
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
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
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
            acceptance_callback_payment: acceptance_callback_payment,
            submission_callback_gas: submission_callback_gas,
            submission_callback_payment: submission_callback_payment,
            acceptance_callback: acceptance_callback,
            submission_callback: completion_callback
        });
        require(
            payment <= msg.value,
            "Insufficient funds to execute the request"
        );
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
        uint256 acceptance_callback_payment,
        uint256 submission_callback_gas,
        uint256 submission_callback_payment,
        function(CRTT.Response memory) external payable acceptance_callback,
        function(CRTT.Response memory) external payable completion_callback
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
            acceptance_callback_payment: acceptance_callback_payment,
            submission_callback_gas: submission_callback_gas,
            submission_callback_payment: submission_callback_payment,
            acceptance_callback: acceptance_callback,
            submission_callback: completion_callback
        });
        require(
            payment <= msg.value,
            "Insufficient funds to execute the request"
        );
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

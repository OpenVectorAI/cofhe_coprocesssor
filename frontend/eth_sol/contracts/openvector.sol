// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "./lib.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "hardhat/console.sol";

contract OpenVectorCOFHEExecutor is Ownable, COFHExecutor {
    // 25000 for misc gas cost
    // 3*21000 for the gas cost of the transactions(1 acceptance, 1 submission and 1 payback)
    uint256 constant BUFFER_GAS_COST_FOR_CALLBACKS = 25000; // 10k gwei
    uint256 constant BASE_GAS_COST =
        (BUFFER_GAS_COST_FOR_CALLBACKS * 3 + 25000 + 3 * 21000) * (1000000000); // 163000

    struct RequestWithPaymentInfo {
        CRTT.Request request;
        uint256 payment;
        uint256 op_cost;
    }

    struct DataRetrievalRequestWithPaymentInfo {
        CRTT.DataRetrievalRequest request;
        uint256 payment;
        uint256 op_cost;
    }

    struct DataStoreRequestWithPaymentInfo {
        CRTT.DataStoreRequest request;
        uint256 payment;
        uint256 op_cost;
    }

    struct ConfidentialCoinRequestWithPaymentInfo {
        CRTT.ConfidentialCoinRequest request;
        uint256 payment;
        uint256 op_cost;
    }

    CRTT.RequestID public last_request_id;
    CRTT.RequestID public last_data_request_id;
    CRTT.RequestID public last_data_store_request_id;
    CRTT.RequestID public last_confidential_coin_request_id;

    mapping(CRTT.RequestID => RequestWithPaymentInfo) public pending_requests;
    mapping(CRTT.RequestID => DataRetrievalRequestWithPaymentInfo)
        public pending_data_requests;
    mapping(CRTT.RequestID => DataStoreRequestWithPaymentInfo)
        public pending_data_store_requests;
    mapping(CRTT.RequestID => ConfidentialCoinRequestWithPaymentInfo)
        public pending_confidential_coin_requests;

    // Cost is in gwei
    // zero cost means the operation is not supported
    mapping(CRTT.Operation => uint256) public operation_cost;
    // decryption and reencryption cost are the same
    uint256 public decryption_cost;
    uint256 public data_store_cost;
    uint256 public confidential_coin_request_cost;

    constructor() Ownable(msg.sender) {
        last_request_id = CRTT.getDefaultRequestID();
        last_data_request_id = CRTT.getDefaultRequestID();
        last_data_store_request_id = CRTT.getDefaultRequestID();
        last_confidential_coin_request_id = CRTT.getDefaultRequestID();
        decryption_cost = 0;
        data_store_cost = 0;
        confidential_coin_request_cost = 0;
        // the mapping will default to 0
    }

    function setPrice(
        CRTT.Operation operation,
        uint256 price
    ) public onlyOwner {
        operation_cost[operation] = price;
    }

    function setDecryptionPrice(uint256 price) public onlyOwner {
        decryption_cost = price;
    }

    function setDataStorePrice(uint256 price) public onlyOwner {
        data_store_cost = price;
    }

    function setConfidentialCoinRequestPrice(uint256 price) public onlyOwner {
        confidential_coin_request_cost = price;
    }

    function executeRequest(
        CRTT.Request calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing Request");
        console.log("Operation: %d", (uint)(request.operation));
        uint256 price = operation_cost[request.operation];
        require(price > 0, "Operation not supported");
        require(msg.value == request.payment, "Fund mismatch with the request");
        require(
            msg.value >=
                (price +
                    BASE_GAS_COST +
                    request.acceptance_callback_gas +
                    request.submission_callback_gas +
                    request.payment_callback_gas),
            "Insufficient funds to execute the request"
        );
        console.log("Request requirements met");

        last_request_id = CRTT.incrementRequestID(last_request_id);

        pending_requests[last_request_id] = RequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            op_cost: (price + BASE_GAS_COST + request.payment_callback_gas)
        });

        emit CRTT.NewRequest(last_request_id, CRTT.RequestType.OPERATION);
        console.log(
            "Request emitted for request %d",
            CRTT.requestIDToUint128(last_request_id)
        );
        return last_request_id;
    }

    function executeRequest(
        CRTT.DataRetrievalRequest calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing Data Retrieval Request");
        require(msg.value == request.payment, "Fund mismatch with the request");
        uint256 required_payment = BASE_GAS_COST +
            request.callback_gas +
            request.payment_callback_gas;
        if (
            request.requested_type == CRTT.DataRequestedType.DECRYPTED ||
            request.requested_type == CRTT.DataRequestedType.REENCRYPTED
        ) {
            required_payment += decryption_cost;
            require(decryption_cost > 0, "Operation not supported");
        }
        require(
            msg.value >= required_payment,
            "Insufficient funds to execute the request"
        );
        console.log("Data Retrieval Request requirements met");
        last_data_request_id = CRTT.incrementRequestID(last_data_request_id);

        pending_data_requests[
            last_data_request_id
        ] = DataRetrievalRequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            op_cost: (decryption_cost +
                BASE_GAS_COST +
                request.payment_callback_gas)
        });

        emit CRTT.NewRequest(
            last_data_request_id,
            CRTT.RequestType.DATA_RETRIEVAL
        );
        console.log(
            "Data Retrieval Request emitted, for request %d",
            CRTT.requestIDToUint128(last_data_request_id)
        );
        return last_data_request_id;
    }

    function executeRequest(
        CRTT.DataStoreRequest calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing Data Store Request");
        require(data_store_cost > 0, "Data Store operation is not supported");
        require(msg.value == request.payment, "Fund mismatch with the request");
        require(
            msg.value >=
                BASE_GAS_COST +
                    data_store_cost +
                    request.acceptance_callback_gas +
                    request.submission_callback_gas +
                    request.payment_callback_gas,
            "Insufficient funds to execute the request"
        );
        console.log("Data Store Request requirements met");
        last_data_store_request_id = CRTT.incrementRequestID(
            last_data_store_request_id
        );

        pending_data_store_requests[
            last_data_store_request_id
        ] = DataStoreRequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            op_cost: (data_store_cost +
                BASE_GAS_COST +
                request.payment_callback_gas)
        });

        emit CRTT.NewRequest(
            last_data_store_request_id,
            CRTT.RequestType.DATA_STORE
        );
        console.log(
            "Data Store Request emitted for request %d",
            CRTT.requestIDToUint128(last_data_store_request_id)
        );
        return last_data_store_request_id;
    }

    function executeRequest(
        CRTT.ConfidentialCoinRequest calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing ConfidentialCoin Request");
        require(
            confidential_coin_request_cost > 0,
            "ConfidentialCoin operation is not supported"
        );
        require(
            msg.value >=
                BASE_GAS_COST +
                    confidential_coin_request_cost +
                    request.callback_gas,
            "Insufficient funds to execute the request"
        );
        console.log("ConfidentialCoin Request requirements met");
        last_confidential_coin_request_id = CRTT.incrementRequestID(
            last_confidential_coin_request_id
        );

        pending_confidential_coin_requests[
            last_confidential_coin_request_id
        ] = ConfidentialCoinRequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            op_cost: (confidential_coin_request_cost +
                BASE_GAS_COST +
                request.payment_callback_gas)
        });

        emit CRTT.NewRequest(
            last_confidential_coin_request_id,
            CRTT.RequestType.CONFIDENTIAL_COIN
        );
        console.log(
            "ConfidentialCoin Request emitted for request %d",
            CRTT.requestIDToUint128(last_confidential_coin_request_id)
        );
        return last_confidential_coin_request_id;
    }

    function submitResponse(
        CRTT.Response calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        if (response.status == CRTT.ResponseStatus.ACCEPTED) {
            console.log(
                "Calling the acceptance callback for request %d",
                CRTT.requestIDToUint128(response.request_id)
            );
            console.log(
                "acceptance_callback_gas: %d",
                pending_requests[response.request_id]
                    .request
                    .acceptance_callback_gas / 1000000000
            );
            try
                pending_requests[response.request_id]
                    .request
                    .acceptance_callback{
                    gas: (
                        pending_requests[response.request_id]
                            .request
                            .acceptance_callback_gas
                    ) / 1000000000
                }(response)
            {
                console.log("Acceptance Callback successful");
            } catch {
                console.log("Error in Acceptance Callback");
            }
        } else {
            console.log(
                "Calling the submission callback for request %d",
                CRTT.requestIDToUint128(response.request_id)
            );
            console.log(
                "submission_callback_gas: %d",
                pending_requests[response.request_id]
                    .request
                    .submission_callback_gas / 1000000000
            );
            try
                pending_requests[response.request_id]
                    .request
                    .submission_callback{
                    gas: (
                        pending_requests[response.request_id]
                            .request
                            .submission_callback_gas
                    ) / 1000000000
                }(response)
            {
                console.log("Submission Callback successful");
            } catch {
                console.log("Error in Submission Callback");
            }
        }
        uint256 gas_used = gas_available - gasleft();
        if (gas_used < BUFFER_GAS_COST_FOR_CALLBACKS) {
            gas_used = 0;
        } else {
            gas_used -= BUFFER_GAS_COST_FOR_CALLBACKS;
        }
        uint256 wei_used = gas_used * tx.gasprice;

        pending_requests[response.request_id].op_cost += wei_used;

        if (response.status != CRTT.ResponseStatus.ACCEPTED) {
            uint256 amount_to_transfer = pending_requests[response.request_id]
                .payment - pending_requests[response.request_id].op_cost;
            if (amount_to_transfer > 0) {
                console.log(
                    "Transferring %d for request id %d",
                    amount_to_transfer,
                    CRTT.requestIDToUint128(response.request_id)
                );
                try
                    pending_requests[response.request_id]
                        .request
                        .payment_callback{
                        gas: (
                            pending_requests[response.request_id]
                                .request
                                .payment_callback_gas
                        ) / 1000000000,
                        value: amount_to_transfer
                    }(response.request_id)
                {
                    console.log("Payment Callback successful");
                } catch {
                    console.log("Error in Payment Callback");
                }
            }
            delete pending_requests[response.request_id];
        }
    }

    function submitDataRetrievalResponse(
        CRTT.DataRetrievalResponse calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        console.log(
            "Calling the callback for data retrieval request %d",
            CRTT.requestIDToUint128(response.request_id)
        );
        console.log(
            "callback_gas: %d",
            pending_data_requests[response.request_id].request.callback_gas /
                1000000000
        );
        try
            pending_data_requests[response.request_id].request.callback{
                gas: (
                    pending_data_requests[response.request_id]
                        .request
                        .callback_gas
                ) / 1000000000
            }(response)
        {
            console.log("Data Retrieve Callback successful");
        } catch {
            console.log("Error in Data Retrieve Callback");
        }
        uint256 gas_used = gas_available - gasleft();
        if (gas_used < BUFFER_GAS_COST_FOR_CALLBACKS) {
            gas_used = 0;
        } else {
            gas_used -= BUFFER_GAS_COST_FOR_CALLBACKS;
        }
        uint256 wei_used = gas_used * tx.gasprice;

        uint256 amount_to_transfer = pending_data_requests[response.request_id]
            .payment -
            wei_used -
            pending_data_requests[response.request_id].op_cost;
        if (amount_to_transfer > 0) {
            console.log(
                "Transferring %d  for request id %d",
                amount_to_transfer,
                CRTT.requestIDToUint128(response.request_id)
            );
            try
                pending_data_requests[response.request_id]
                    .request
                    .payment_callback{
                    gas: (
                        pending_data_requests[response.request_id]
                            .request
                            .payment_callback_gas
                    ) / 1000000000,
                    value: amount_to_transfer
                }(response.request_id)
            {
                console.log("Payment Callback successful");
            } catch {
                console.log("Error in Payment Callback");
            }
        }
        delete pending_data_requests[response.request_id];
    }

    function submitDataStoreResponse(
        CRTT.DataStoreResponse calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();

        if (response.status == CRTT.ResponseStatus.ACCEPTED) {
            console.log(
                "Calling the acceptance callback for data store request %d",
                CRTT.requestIDToUint128(response.request_id)
            );
            console.log(
                "acceptance_callback_gas: %d",
                pending_data_store_requests[response.request_id]
                    .request
                    .acceptance_callback_gas / 1000000000
            );
            try
                pending_data_store_requests[response.request_id]
                    .request
                    .acceptance_callback{
                    gas: (
                        pending_data_store_requests[response.request_id]
                            .request
                            .acceptance_callback_gas
                    ) / 1000000000
                }(response)
            {
                console.log("Data Store Acceptance Callback successful");
            } catch {
                console.log("Error in Data Store Acceptance Callback");
            }
        } else {
            console.log(
                "Calling the submission callback for data store request %d",
                CRTT.requestIDToUint128(response.request_id)
            );
            console.log(
                "submission_callback_gas: %d",
                pending_data_store_requests[response.request_id]
                    .request
                    .submission_callback_gas / 1000000000
            );
            try
                pending_data_store_requests[response.request_id]
                    .request
                    .submission_callback{
                    gas: (
                        pending_data_store_requests[response.request_id]
                            .request
                            .submission_callback_gas
                    ) / 1000000000
                }(response)
            {
                console.log("Data Store Submission Callback successful");
            } catch {
                console.log("Error in Data Store Submission Callback");
            }
        }
        uint256 gas_used = gas_available - gasleft();
        if (gas_used < BUFFER_GAS_COST_FOR_CALLBACKS) {
            gas_used = 0;
        } else {
            gas_used -= BUFFER_GAS_COST_FOR_CALLBACKS;
        }
        uint256 wei_used = gas_used * tx.gasprice;

        pending_data_store_requests[response.request_id].op_cost += wei_used;

        if (response.status != CRTT.ResponseStatus.ACCEPTED) {
            uint256 amount_to_transfer = pending_data_store_requests[
                response.request_id
            ].payment -
                pending_data_store_requests[response.request_id].op_cost;
            if (amount_to_transfer > 0) {
                console.log(
                    "Transferring %d for request id %d",
                    amount_to_transfer,
                    CRTT.requestIDToUint128(response.request_id)
                );
                try
                    pending_data_store_requests[response.request_id]
                        .request
                        .payment_callback{
                        gas: (
                            pending_data_store_requests[response.request_id]
                                .request
                                .payment_callback_gas
                        ) / 1000000000,
                        value: amount_to_transfer
                    }(response.request_id)
                {
                    console.log("Payment Callback successful");
                } catch {
                    console.log("Error in Payment Callback");
                }
            }
            delete pending_data_store_requests[response.request_id];
        }
    }

    function submitConfidentialCoinResponse(
        CRTT.ConfidentialCoinResponse calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        console.log(
            "Calling the callback for confidential coin request %d",
            CRTT.requestIDToUint128(response.request_id)
        );
        console.log(
            "acceptance_callback_gas: %d",
            pending_confidential_coin_requests[response.request_id]
                .request
                .callback_gas / 1000000000
        );
        try
            pending_confidential_coin_requests[response.request_id]
                .request
                .callback{
                gas: (
                    pending_confidential_coin_requests[response.request_id]
                        .request
                        .callback_gas
                ) / 1000000000
            }(response)
        {
            console.log("ConfidentialCoin Callback successful");
        } catch {
            console.log("Error in ConfidentialCoin Callback");
        }

        uint256 gas_used = gas_available - gasleft();
        if (gas_used < BUFFER_GAS_COST_FOR_CALLBACKS) {
            gas_used = 0;
        } else {
            gas_used -= BUFFER_GAS_COST_FOR_CALLBACKS;
        }
        uint256 wei_used = gas_used * tx.gasprice;
        uint256 amount_to_transfer = pending_confidential_coin_requests[
            response.request_id
        ].payment -
            pending_confidential_coin_requests[response.request_id].op_cost -
            wei_used;
        if (amount_to_transfer > 0) {
            console.log(
                "Transferring %d  for request id %d",
                amount_to_transfer,
                CRTT.requestIDToUint128(response.request_id)
            );
            try
                pending_confidential_coin_requests[response.request_id]
                    .request
                    .payment_callback{
                    gas: (
                        pending_confidential_coin_requests[response.request_id]
                            .request
                            .payment_callback_gas
                    ) / 1000000000,
                    value: amount_to_transfer
                }(response.request_id)
            {
                console.log("Payment Callback successful");
            } catch {
                console.log("Error in Payment Callback");
            }
        }
        delete pending_confidential_coin_requests[response.request_id];
    }

    function withdraw() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    function withdraw(uint128 amount) external onlyOwner {
        require(
            amount <= address(this).balance,
            "Insufficient balance to withdraw"
        );
        payable(owner()).transfer(amount);
    }

    function getBalance() external view onlyOwner returns (uint128) {
        return uint128(address(this).balance);
    }
}

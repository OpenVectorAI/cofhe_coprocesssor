// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "./lib.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "hardhat/console.sol";

contract OpenVectorCOFHEExecutor is Ownable, COFHExecutor {
    // 10000 for the base gas cost
    // 10000 for misc gas cost
    // 2*21000 for the gas cost of the transactions
    uint128 constant BASE_GAS_COST = 10000 + 10000 + 2 * 21000; // 62000

    struct RequestWithPaymentInfo {
        CRTT.Request request;
        uint256 payment;
        address payable requestee;
    }

    struct DataRetrievalRequestWithPaymentInfo {
        CRTT.DataRetrievalRequest request;
        uint256 payment;
        address payable requestee;
    }

    struct DataStoreRequestWithPaymentInfo {
        CRTT.DataStoreRequest request;
        uint256 payment;
        address payable requestee;
    }

    uint128 public last_request_id;
    uint128 public last_data_request_id;
    uint128 public last_data_store_request_id;

    mapping(CRTT.RequestID => RequestWithPaymentInfo) public pending_requests;
    mapping(CRTT.RequestID => DataRetrievalRequestWithPaymentInfo)
        public pending_data_requests;
    mapping(CRTT.RequestID => DataStoreRequestWithPaymentInfo)
        public pending_data_store_requests;

    // Cost is in gwei
    // zero cost means the operation is not supported
    mapping(CRTT.Operation => uint256) public operation_cost;
    // decryption and reencryption cost are the same
    uint256 public decryption_cost;
    uint256 public data_store_cost;

    constructor() Ownable(msg.sender) {
        last_request_id = 0;
        last_data_request_id = 0;
        last_data_store_request_id = 0;
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
                    request.acceptance_callback_payment +
                    request.submission_callback_gas +
                    request.submission_callback_payment),
            "Insufficient funds to execute the request"
        );
        console.log("Request requirements met");

        uint128 requestId = last_request_id++;
        CRTT.RequestID requestIdWrapped = CRTT.RequestID.wrap(requestId);

        pending_requests[requestIdWrapped] = RequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            requestee: payable(msg.sender)
        });

        emit CRTT.NewRequest(requestIdWrapped, CRTT.RequestType.OPERATION);
        console.log("Request emitted for request %d", requestId);
        return requestIdWrapped;
    }

    function executeRequest(
        CRTT.DataRetrievalRequest calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing Data Retrieval Request");
        require(msg.value == request.payment, "Fund mismatch with the request");
        uint256 required_payment = BASE_GAS_COST +
            request.callback_gas +
            request.callback_payment;
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
        uint128 requestId = last_data_request_id++;
        CRTT.RequestID requestIdWrapped = CRTT.RequestID.wrap(requestId);

        pending_data_requests[
            requestIdWrapped
        ] = DataRetrievalRequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            requestee: payable(msg.sender)
        });

        emit CRTT.NewRequest(requestIdWrapped, CRTT.RequestType.DATA_RETRIEVAL);
        console.log(
            "Data Retrieval Request emitted, for request %d",
            requestId
        );
        return requestIdWrapped;
    }

    function executeRequest(
        CRTT.DataStoreRequest calldata request
    ) external payable returns (CRTT.RequestID) {
        console.log("Executing Data Store Request");
        require(msg.value == request.payment, "Fund mismatch with the request");
        require(
            msg.value >=
                BASE_GAS_COST +
                    data_store_cost +
                    request.acceptance_callback_gas +
                    request.acceptance_callback_payment +
                    request.submission_callback_gas +
                    request.submission_callback_payment,
            "Insufficient funds to execute the request"
        );
        console.log("Data Store Request requirements met");
        uint128 requestId = last_data_store_request_id++;
        CRTT.RequestID requestIdWrapped = CRTT.RequestID.wrap(requestId);

        pending_data_store_requests[
            requestIdWrapped
        ] = DataStoreRequestWithPaymentInfo({
            request: request,
            payment: msg.value,
            requestee: payable(msg.sender)
        });

        emit CRTT.NewRequest(requestIdWrapped, CRTT.RequestType.DATA_STORE);
        console.log("Data Store Request emitted for request %d", requestId);
        return requestIdWrapped;
    }

    function submitResponse(
        CRTT.Response calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        uint256 payment_used = 0;
        if (response.status == CRTT.ResponseStatus.ACCEPTED) {
            console.log(
                "Calling the acceptance callback for request %d",
                CRTT.RequestID.unwrap(response.request_id)
            );
            console.log(
                "acceptance_callback_payment: %d",
                pending_requests[response.request_id]
                    .request
                    .acceptance_callback_payment
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
                    value: pending_requests[response.request_id]
                        .request
                        .acceptance_callback_payment,
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
            payment_used = pending_requests[response.request_id]
                .request
                .acceptance_callback_payment;
        } else {
            console.log(
                "Calling the submission callback for request %d",
                CRTT.RequestID.unwrap(response.request_id)
            );
            console.log(
                "submission_callback_payment: %d",
                pending_requests[response.request_id]
                    .request
                    .submission_callback_payment
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
                    value: pending_requests[response.request_id]
                        .request
                        .submission_callback_payment,
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
            payment_used = pending_requests[response.request_id]
                .request
                .submission_callback_payment;
        }
        uint256 gas_used = gas_available - gasleft();
        uint256 wei_used = gas_used * tx.gasprice + payment_used;

        pending_requests[response.request_id].payment -= wei_used;

        // transfer the remaining to the requestee
        if (response.status != CRTT.ResponseStatus.ACCEPTED) {
            (bool success, ) = pending_requests[response.request_id]
                .requestee
                .call{value: pending_requests[response.request_id].payment}("");
            delete pending_requests[response.request_id];
        }
    }

    function submitDataRetrievalResponse(
        CRTT.DataRetrievalResponse calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        console.log(
            "Calling the callback for data retrieval request %d",
            CRTT.RequestID.unwrap(response.request_id)
        );
        console.log(
            "callback_payment: %d",
            pending_data_requests[response.request_id].request.callback_payment
        );
        console.log(
            "callback_gas: %d",
            pending_data_requests[response.request_id].request.callback_gas /
                1000000000
        );
        try
            pending_data_requests[response.request_id].request.callback{
                value: pending_data_requests[response.request_id]
                    .request
                    .callback_payment,
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
        uint256 payment_used = pending_data_requests[response.request_id]
            .request
            .callback_payment;
        uint256 wei_used = gas_used * tx.gasprice + payment_used;

        pending_data_requests[response.request_id].payment -= wei_used;

        // transfer the remaining to the requestee
        if (response.status != CRTT.ResponseStatus.ACCEPTED) {
            (bool success, ) = pending_data_requests[response.request_id]
                .requestee
                .call{
                value: pending_data_requests[response.request_id].payment
            }("");
            delete pending_data_requests[response.request_id];
        }
    }

    function submitDataStoreResponse(
        CRTT.DataStoreResponse calldata response
    ) external onlyOwner {
        uint256 gas_available = gasleft();
        uint256 payment_used = 0;

        if (response.status == CRTT.ResponseStatus.ACCEPTED) {
            console.log(
                "Calling the acceptance callback for data store request %d",
                CRTT.RequestID.unwrap(response.request_id)
            );
            console.log(
                "acceptance_callback_payment: %d",
                pending_data_store_requests[response.request_id]
                    .request
                    .acceptance_callback_payment
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
                    value: pending_data_store_requests[response.request_id]
                        .request
                        .acceptance_callback_payment,
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
            payment_used = pending_data_store_requests[response.request_id]
                .request
                .acceptance_callback_payment;
        } else {
            console.log(
                "Calling the submission callback for data store request %d",
                CRTT.RequestID.unwrap(response.request_id)
            );
            console.log(
                "submission_callback_payment: %d",
                pending_data_store_requests[response.request_id]
                    .request
                    .submission_callback_payment
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
                    value: pending_data_store_requests[response.request_id]
                        .request
                        .submission_callback_payment,
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
            payment_used = pending_data_store_requests[response.request_id]
                .request
                .submission_callback_payment;
        }
        uint256 gas_used = gas_available - gasleft();
        uint256 wei_used = gas_used * tx.gasprice + payment_used;

        pending_data_store_requests[response.request_id].payment -= wei_used;

        // transfer the remaining to the requestee
        if (response.status != CRTT.ResponseStatus.ACCEPTED) {
            (bool success, ) = pending_data_store_requests[response.request_id]
                .requestee
                .call{
                value: pending_data_store_requests[response.request_id].payment
            }("");
            delete pending_data_store_requests[response.request_id];
        }
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

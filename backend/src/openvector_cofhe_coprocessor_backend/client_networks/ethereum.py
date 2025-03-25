from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Tuple, TypedDict
import uuid
from typing_extensions import override
from dataclasses import dataclass
from enum import Enum
from queue import Queue

import asyncio
from threading import Thread, Event

from web3 import AsyncWeb3, WebSocketProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from web3.types import Wei
from web3.contract import AsyncContract
from eth_typing import Address

from openvector_cofhe_coprocessor_backend.core.request_response import (
    Request,
    Operand,
    DataType,
    OperandLocation,
    OperandEncryptionScheme,
    Operation,
    Response,
    ResponseStatus,
)
from openvector_cofhe_coprocessor_backend.core.client_network import IClientNetwork


@dataclass(frozen=True, slots=True)
class EthereumClientConfig:
    provider: str
    contract_address: str
    contract_abi_file_path: str
    owner_account_address: str
    owner_account_private_key: str


# both are uint128
EthereumDataKey = int
EthereumRequestID = int


# values must be same as solidity data types
SolidityDataType = int


class EthereumDataType(Enum):
    BIT = 0
    UINT32 = 1


def encode_to_python_data_type(data_type: SolidityDataType) -> EthereumDataType:
    # if data_type == 0:
    #     return EthereumDataType.BIT
    # elif data_type == 1:
    #     return EthereumDataType.UINT32
    # else:
    #     raise ValueError("Invalid data type")
    # As values are gaurenteed to be same
    return EthereumDataType(data_type)


def encode_to_solidity_data_type(data_type: EthereumDataType) -> SolidityDataType:
    # if data_type == EthereumDataType.BIT:
    #     return 0
    # elif data_type == EthereumDataType.UINT32:
    #     return 1
    # else:
    #     raise ValueError("Invalid data type")
    # As values are gaurenteed to be same
    return data_type.value


def convert_to_native_data_type(data_type: EthereumDataType) -> DataType:
    if data_type == EthereumDataType.UINT32:
        return DataType.UINT32
    elif data_type == EthereumDataType.BIT:
        return DataType.BIT
    else:
        raise ValueError("Invalid data type")


def convert_from_native_data_type(data_type: DataType) -> EthereumDataType:
    if data_type == DataType.UINT32:
        return EthereumDataType.UINT32
    elif data_type == DataType.BIT:
        return EthereumDataType.BIT
    else:
        raise ValueError("Invalid data type")


SolidityOperation = int


class EthereumOperation(Enum):
    ADD = 0
    SUB = 1
    LT = 2
    GT = 3
    EQ = 4
    LTEQ = 5
    GTEQ = 6
    NAND = 7


def encode_to_python_operation(
    operation_type: SolidityOperation,
) -> EthereumOperation:
    return EthereumOperation(operation_type)


def encode_to_solidity_operation(
    operation_type: EthereumOperation,
) -> SolidityOperation:
    return operation_type.value


def convert_to_native_operation(operation_type: EthereumOperation) -> Operation:
    if operation_type == EthereumOperation.ADD:
        return Operation.ADD
    elif operation_type == EthereumOperation.SUB:
        return Operation.SUB
    elif operation_type == EthereumOperation.LT:
        return Operation.LT
    elif operation_type == EthereumOperation.GT:
        return Operation.GT
    elif operation_type == EthereumOperation.EQ:
        return Operation.EQ
    elif operation_type == EthereumOperation.LTEQ:
        return Operation.LTEQ
    elif operation_type == EthereumOperation.GTEQ:
        return Operation.GTEQ
    elif operation_type == EthereumOperation.NAND:
        return Operation.NAND
    else:
        raise ValueError("Invalid operation type")


def convert_from_native_operation(operation_type: Operation) -> EthereumOperation:
    if operation_type == Operation.ADD:
        return EthereumOperation.ADD
    elif operation_type == Operation.SUB:
        return EthereumOperation.SUB
    elif operation_type == Operation.LT:
        return EthereumOperation.LT
    elif operation_type == Operation.GT:
        return EthereumOperation.GT
    elif operation_type == Operation.EQ:
        return EthereumOperation.EQ
    elif operation_type == Operation.LTEQ:
        return EthereumOperation.LTEQ
    elif operation_type == Operation.GTEQ:
        return EthereumOperation.GTEQ
    elif operation_type == Operation.NAND:
        return EthereumOperation.NAND
    else:
        raise ValueError("Invalid operation type")


SolidityOperandLocation = int


class EthereumOperandLocation(Enum):
    STORAGE_KEY = 0
    VALUE = 1


def encode_to_python_location(
    location_type: SolidityOperandLocation,
) -> EthereumOperandLocation:
    return EthereumOperandLocation(location_type)


def encode_to_solidity_location(
    location_type: EthereumOperandLocation,
) -> SolidityOperandLocation:
    return location_type.value


def convert_to_native_location(
    location_type: EthereumOperandLocation,
) -> OperandLocation:
    if location_type == EthereumOperandLocation.STORAGE_KEY:
        return OperandLocation.STORAGE_KEY
    elif location_type == EthereumOperandLocation.VALUE:
        return OperandLocation.VALUE
    else:
        raise ValueError("Invalid operand location type")


def convert_from_native_location(
    location_type: OperandLocation,
) -> EthereumOperandLocation:
    if location_type == OperandLocation.STORAGE_KEY:
        return EthereumOperandLocation.STORAGE_KEY
    elif location_type == OperandLocation.VALUE:
        return EthereumOperandLocation.VALUE
    else:
        raise ValueError("Invalid operand location type")


SolidityOperandEncryptionScheme = int


class EthereumOperandEncryptionScheme(Enum):
    NONE = 0
    CLHSM2k = 1
    RSA = 2


def encode_to_python_operand_encryption_scheme(
    encryption_scheme: SolidityOperandEncryptionScheme,
) -> EthereumOperandEncryptionScheme:
    return EthereumOperandEncryptionScheme(encryption_scheme)


def encode_to_solidity_operand_encryption_scheme(
    encryption_scheme: EthereumOperandEncryptionScheme,
) -> SolidityOperandEncryptionScheme:
    return encryption_scheme.value


def convert_to_native_operand_encryption_scheme(
    encryption_scheme: EthereumOperandEncryptionScheme,
) -> OperandEncryptionScheme:
    if encryption_scheme == EthereumOperandEncryptionScheme.NONE:
        return OperandEncryptionScheme.NONE
    elif encryption_scheme == EthereumOperandEncryptionScheme.CLHSM2k:
        return OperandEncryptionScheme.CLHSM2k
    elif encryption_scheme == EthereumOperandEncryptionScheme.RSA:
        return OperandEncryptionScheme.RSA
    else:
        raise ValueError("Invalid operand encryption type")


def convert_from_native_operand_encryption_scheme(
    encryption_scheme: OperandEncryptionScheme,
) -> EthereumOperandEncryptionScheme:
    if encryption_scheme == OperandEncryptionScheme.NONE:
        return EthereumOperandEncryptionScheme.NONE
    elif encryption_scheme == OperandEncryptionScheme.CLHSM2k:
        return EthereumOperandEncryptionScheme.CLHSM2k
    elif encryption_scheme == OperandEncryptionScheme.RSA:
        return EthereumOperandEncryptionScheme.RSA
    else:
        raise ValueError("Invalid operand encryption type")


SolidityOperand = Tuple[
    SolidityDataType, SolidityOperandLocation, SolidityOperandEncryptionScheme, bytes
]


@dataclass(frozen=True, slots=True)
class EthereumOperand:
    data_type: EthereumDataType
    location: EthereumOperandLocation
    encryption_scheme: EthereumOperandEncryptionScheme
    data: bytes


def default_operand() -> EthereumOperand:
    return EthereumOperand(
        data_type=EthereumDataType.BIT,
        location=EthereumOperandLocation.STORAGE_KEY,
        encryption_scheme=EthereumOperandEncryptionScheme.NONE,
        data=b"",
    )


def encode_to_python_operand(operand: SolidityOperand) -> EthereumOperand:
    return EthereumOperand(
        data_type=encode_to_python_data_type(operand[0]),
        location=encode_to_python_location(operand[1]),
        encryption_scheme=encode_to_python_operand_encryption_scheme(operand[2]),
        data=operand[3],
    )


def encode_to_solidity_operand(operand: EthereumOperand) -> SolidityOperand:
    return (
        encode_to_solidity_data_type(operand.data_type),
        encode_to_solidity_location(operand.location),
        encode_to_solidity_operand_encryption_scheme(operand.encryption_scheme),
        operand.data,
    )


def convert_to_native_operand(operand: EthereumOperand) -> Operand:
    # if operand.location!=EthereumOperandLocation.STORAGE_KEY:
    #     raise ValueError("Invalid operand location type")

    return Operand(
        data_type=convert_to_native_data_type(operand.data_type),
        location=convert_to_native_location(operand.location),
        encryption_scheme=convert_to_native_operand_encryption_scheme(
            operand.encryption_scheme
        ),
        data=operand.data,
    )


def convert_from_native_operand(operand: Operand | None) -> EthereumOperand:

    if operand is None:
        return default_operand()

    if operand.location != OperandLocation.STORAGE_KEY:
        raise ValueError("Invalid operand location type")

    return EthereumOperand(
        data_type=convert_from_native_data_type(operand.data_type),
        location=convert_from_native_location(operand.location),
        encryption_scheme=convert_from_native_operand_encryption_scheme(
            operand.encryption_scheme
        ),
        data=operand.data,
    )


SolidityRequest = Tuple[
    SolidityOperation,
    SolidityOperand,
    SolidityOperand,
    int,
    int,
    int,
    int,
    int,
    Any,
    Any,
]


@dataclass(frozen=True, slots=True)
class EthereumRequest:
    operation: EthereumOperation
    op1: EthereumOperand
    op2: EthereumOperand
    payment: Wei
    acceptance_callback_gas: Wei
    acceptance_callback_payment: Wei
    submission_callback_gas: Wei
    submission_callback_payment: Wei
    # callback funcs acceptance callback and submission callback are not required here
    acceptance_callback: Any
    submission_callback: Any


def encode_to_python_request(request: SolidityRequest) -> EthereumRequest:
    return EthereumRequest(
        operation=encode_to_python_operation(request[0]),
        op1=encode_to_python_operand(request[1]),
        op2=encode_to_python_operand(request[2]),
        payment=Wei(request[3]),
        acceptance_callback_gas=Wei(request[4]),
        acceptance_callback_payment=Wei(request[5]),
        submission_callback_gas=Wei(request[6]),
        submission_callback_payment=Wei(request[7]),
        acceptance_callback=request[8],
        submission_callback=request[9],
    )


# Wont be used
def encode_to_solidity_request(request: EthereumRequest) -> SolidityRequest:
    return (
        encode_to_solidity_operation(request.operation),
        encode_to_solidity_operand(request.op1),
        encode_to_solidity_operand(request.op2),
        int(request.payment),
        int(request.acceptance_callback_gas),
        int(request.acceptance_callback_payment),
        int(request.submission_callback_gas),
        int(request.submission_callback_payment),
        request.acceptance_callback,
        request.submission_callback,
    )


def convert_to_native_request(request: EthereumRequest) -> Request:
    return Request(
        id=uuid.uuid4().hex,
        operation=convert_to_native_operation(request.operation),
        op1=convert_to_native_operand(request.op1),
        op2=convert_to_native_operand(request.op2),
    )


# wont be used
def convert_from_native_request(request: Request) -> EthereumRequest:
    return EthereumRequest(
        operation=convert_from_native_operation(request.operation),
        op1=convert_from_native_operand(request.op1),
        op2=convert_from_native_operand(request.op2),
        # this makes the function not callable
        payment=Wei(0),
        acceptance_callback_gas=Wei(0),
        acceptance_callback_payment=Wei(0),
        submission_callback_gas=Wei(0),
        submission_callback_payment=Wei(0),
        # this might cause an issue as these are callback functions and not none
        # but currently we never abi encode this so it should be fine
        acceptance_callback=None,
        submission_callback=None,
    )


SolidityResponseStatus = int


class EthereumResponseStatus(Enum):
    ACCEPTED = 0
    SUCCESS = 1
    FAILURE = 2
    INVALID_OPERATION = 3
    INSUFFICIENT_BALANCE = 4
    INVALID_DATA_TYPE = 5
    UNKNOWN_DATA_STORAGE_KEY = 6
    INVALID_ENCRYPTION_SCHEME = 7


def encode_to_python_response_status(
    status: SolidityResponseStatus,
) -> EthereumResponseStatus:
    return EthereumResponseStatus(status)


def encode_to_solidity_response_status(
    status: EthereumResponseStatus,
) -> SolidityResponseStatus:
    return status.value


def convert_to_native_response_status(
    status: EthereumResponseStatus,
) -> ResponseStatus:
    if status == EthereumResponseStatus.ACCEPTED:
        return ResponseStatus.ACCEPTED
    elif status == EthereumResponseStatus.SUCCESS:
        return ResponseStatus.SUCCESS
    elif status == EthereumResponseStatus.FAILURE:
        return ResponseStatus.FAILURE
    elif status == EthereumResponseStatus.INVALID_OPERATION:
        return ResponseStatus.INVALID_OPERATION
    elif status == EthereumResponseStatus.INSUFFICIENT_BALANCE:
        return ResponseStatus.INSUFFICIENT_BALANCE
    elif status == EthereumResponseStatus.INVALID_DATA_TYPE:
        return ResponseStatus.INVALID_DATA_TYPE
    elif status == EthereumResponseStatus.UNKNOWN_DATA_STORAGE_KEY:
        return ResponseStatus.UNKNOWN_DATA_STORAGE_KEY
    elif status == EthereumResponseStatus.INVALID_ENCRYPTION_SCHEME:
        return ResponseStatus.INVALID_ENCRYPTION_SCHEME
    else:
        raise ValueError("Invalid response status")


def convert_from_native_response_status(
    status: ResponseStatus,
) -> EthereumResponseStatus:
    if status == ResponseStatus.ACCEPTED:
        return EthereumResponseStatus.ACCEPTED
    elif status == ResponseStatus.SUCCESS:
        return EthereumResponseStatus.SUCCESS
    elif status == ResponseStatus.FAILURE:
        return EthereumResponseStatus.FAILURE
    elif status == ResponseStatus.INVALID_OPERATION:
        return EthereumResponseStatus.INVALID_OPERATION
    elif status == ResponseStatus.INSUFFICIENT_BALANCE:
        return EthereumResponseStatus.INSUFFICIENT_BALANCE
    elif status == ResponseStatus.INVALID_DATA_TYPE:
        return EthereumResponseStatus.INVALID_DATA_TYPE
    elif status == ResponseStatus.UNKNOWN_DATA_STORAGE_KEY:
        return EthereumResponseStatus.UNKNOWN_DATA_STORAGE_KEY
    elif status == ResponseStatus.INVALID_ENCRYPTION_SCHEME:
        return EthereumResponseStatus.INVALID_ENCRYPTION_SCHEME
    else:
        raise ValueError("Invalid response status")


SolidityResponse = Tuple[SolidityResponseStatus, EthereumRequestID, SolidityOperand]


@dataclass(frozen=True, slots=True)
class EthereumResponse:
    status: EthereumResponseStatus
    request_id: EthereumRequestID
    result: EthereumOperand


def encode_to_python_response(response: SolidityResponse) -> EthereumResponse:
    return EthereumResponse(
        status=encode_to_python_response_status(response[0]),
        request_id=response[1],
        result=encode_to_python_operand(response[2]),
    )


def encode_to_solidity_response(response: EthereumResponse) -> SolidityResponse:

    return (
        encode_to_solidity_response_status(response.status),
        response.request_id,
        encode_to_solidity_operand(response.result),
    )


# wont be used
def convert_to_native_response(response: EthereumResponse) -> Response:
    return Response(
        id=uuid.uuid4().hex,
        # generally this request id represents native request id and not ethereum request id
        request_id=str(response.request_id),
        status=ResponseStatus(response.status.value),
        result=convert_to_native_operand(response.result),
    )


def convert_from_native_response(
    ethereum_request_id: EthereumRequestID, response: Response
) -> EthereumResponse:
    return EthereumResponse(
        status=convert_from_native_response_status(response.status),
        request_id=ethereum_request_id,
        result=convert_from_native_operand(response.result),
    )


SolidityDataRequestedType = int


class EthereumDataRequestedType(Enum):
    ENCRYPTED = 0
    REENCRYPTED = 1
    DECRYPTED = 2


def encode_to_python_data_requested_type(
    data_requested_type: SolidityDataRequestedType,
) -> EthereumDataRequestedType:
    return EthereumDataRequestedType(data_requested_type)


def encode_to_solidity_data_requested_type(
    data_requested_type: EthereumDataRequestedType,
) -> SolidityDataRequestedType:
    return data_requested_type.value


def convert_to_native_data_requested_type(
    data_requested_type: EthereumDataRequestedType,
) -> OperandEncryptionScheme:
    if data_requested_type == EthereumDataRequestedType.ENCRYPTED:
        return OperandEncryptionScheme.CLHSM2k
    elif data_requested_type == EthereumDataRequestedType.DECRYPTED:
        return OperandEncryptionScheme.NONE
    elif data_requested_type == EthereumDataRequestedType.REENCRYPTED:
        return OperandEncryptionScheme.RSA
    else:
        raise ValueError("Invalid data requested type")


def convert_from_native_data_requested_type(
    data_requested_type: OperandEncryptionScheme,
) -> EthereumDataRequestedType:
    if data_requested_type == OperandEncryptionScheme.CLHSM2k:
        return EthereumDataRequestedType.ENCRYPTED
    elif data_requested_type == OperandEncryptionScheme.NONE:
        return EthereumDataRequestedType.DECRYPTED
    elif data_requested_type == OperandEncryptionScheme.RSA:
        return EthereumDataRequestedType.REENCRYPTED
    else:
        raise ValueError("Invalid data requested type")


SolidityValueOperand = Tuple[SolidityDataType, SolidityOperandEncryptionScheme, bytes]


@dataclass(frozen=True, slots=True)
class EthereumValueOperand:
    data_type: EthereumDataType
    encryption_scheme: EthereumOperandEncryptionScheme
    data: bytes


def default_retrieved_operand() -> EthereumValueOperand:
    return EthereumValueOperand(
        data_type=EthereumDataType.BIT,
        encryption_scheme=EthereumOperandEncryptionScheme.NONE,
        data=b"",
    )


def encode_to_python_value_operand(
    retrieved_operand: SolidityValueOperand,
) -> EthereumValueOperand:
    return EthereumValueOperand(
        data_type=encode_to_python_data_type(retrieved_operand[0]),
        encryption_scheme=encode_to_python_operand_encryption_scheme(
            retrieved_operand[1]
        ),
        data=retrieved_operand[2],
    )


def encode_to_solidity_value_operand(
    retrieved_operand: EthereumValueOperand,
) -> SolidityValueOperand:
    return (
        encode_to_solidity_data_type(retrieved_operand.data_type),
        encode_to_solidity_operand_encryption_scheme(
            retrieved_operand.encryption_scheme
        ),
        retrieved_operand.data,
    )


def convert_to_native_value_operand(
    retrieved_operand: EthereumValueOperand,
) -> Operand:
    return Operand(
        data_type=convert_to_native_data_type(retrieved_operand.data_type),
        location=OperandLocation.VALUE,
        encryption_scheme=convert_to_native_operand_encryption_scheme(
            retrieved_operand.encryption_scheme
        ),
        data=retrieved_operand.data,
    )


def convert_from_native_value_operand(
    retrieved_operand: Operand | None,
) -> EthereumValueOperand:
    if retrieved_operand is None:
        return default_retrieved_operand()
    return EthereumValueOperand(
        data_type=convert_from_native_data_type(retrieved_operand.data_type),
        encryption_scheme=convert_from_native_operand_encryption_scheme(
            retrieved_operand.encryption_scheme
        ),
        data=retrieved_operand.data,
    )


SolidityDataRetrievalRequest = Tuple[
    SolidityDataRequestedType, EthereumDataKey, int, int, int, Any, bytes
]


@dataclass(frozen=True, slots=True)
class EthereumDataRetrievalRequest:
    requested_type: EthereumDataRequestedType
    key: EthereumDataKey
    payment: Wei
    callback_gas: Wei
    callback_payment: Wei
    # callback func is not required here
    callback: Any
    reencryption_key: bytes


def encode_to_python_data_retrieval_request(
    data_retrieval_request: SolidityDataRetrievalRequest,
) -> EthereumDataRetrievalRequest:
    return EthereumDataRetrievalRequest(
        requested_type=encode_to_python_data_requested_type(data_retrieval_request[0]),
        key=data_retrieval_request[1],
        payment=Wei(data_retrieval_request[2]),
        callback_gas=Wei(data_retrieval_request[3]),
        callback_payment=Wei(data_retrieval_request[4]),
        callback=data_retrieval_request[5],
        reencryption_key=data_retrieval_request[6],
    )


def encode_to_solidity_data_retrieval_request(
    data_retrieval_request: EthereumDataRetrievalRequest,
) -> SolidityDataRetrievalRequest:
    return (
        encode_to_solidity_data_requested_type(data_retrieval_request.requested_type),
        data_retrieval_request.key,
        int(data_retrieval_request.payment),
        int(data_retrieval_request.callback_gas),
        int(data_retrieval_request.callback_payment),
        data_retrieval_request.callback,
        data_retrieval_request.reencryption_key,
    )


def convert_to_native_data_retrieval_request(
    data_retrieval_request: EthereumDataRetrievalRequest,
) -> Request:
    return Request(
        id=uuid.uuid4().hex,
        operation=(
            Operation.RETRIEVE_REENCRYPT
            if data_retrieval_request.requested_type
            != EthereumDataRequestedType.ENCRYPTED
            else Operation.RETRIEVE
        ),
        op1=Operand(
            data_type=DataType.BIT,
            location=OperandLocation.STORAGE_KEY,
            encryption_scheme=convert_to_native_data_requested_type(
                data_retrieval_request.requested_type
            ),
            data=(
                data_retrieval_request.key.to_bytes(16, "big")
                + data_retrieval_request.reencryption_key
            ),
        ),
        op2=Operand(
            data_type=DataType.BIT,
            location=OperandLocation.VALUE,
            encryption_scheme=OperandEncryptionScheme.NONE,
            data=b"",
        ),
    )


# wont be used
def convert_from_native_data_retrieval_request(
    request: Request,
) -> EthereumDataRetrievalRequest:
    if request.operation != Operation.RETRIEVE:
        raise ValueError("Invalid operation type")

    if request.op1.location != OperandLocation.STORAGE_KEY:
        raise ValueError("Invalid operand location type")

    return EthereumDataRetrievalRequest(
        requested_type=convert_from_native_data_requested_type(
            request.op1.encryption_scheme
        ),
        key=int(request.op1.data[:16]),
        # this makes the function not callable
        payment=Wei(0),
        callback_gas=Wei(0),
        callback_payment=Wei(0),
        # this might cause an issue as these are callback functions and not none
        # but currently we never abi encode this so it should be fine
        callback=None,
        reencryption_key=request.op1.data[16:],
    )


SolidityDataRetrievalResponse = Tuple[
    SolidityResponseStatus, EthereumRequestID, SolidityValueOperand
]


@dataclass(frozen=True, slots=True)
class EthereumDataRetrievalResponse:
    status: EthereumResponseStatus
    request_id: EthereumRequestID
    result: EthereumValueOperand


def encode_to_python_data_retrieval_response(
    data_retrieval_response: SolidityDataRetrievalResponse,
) -> EthereumDataRetrievalResponse:
    return EthereumDataRetrievalResponse(
        status=encode_to_python_response_status(data_retrieval_response[0]),
        request_id=data_retrieval_response[1],
        result=encode_to_python_value_operand(data_retrieval_response[2]),
    )


def encode_to_solidity_data_retrieval_response(
    data_retrieval_response: EthereumDataRetrievalResponse,
) -> SolidityDataRetrievalResponse:
    return (
        encode_to_solidity_response_status(data_retrieval_response.status),
        data_retrieval_response.request_id,
        encode_to_solidity_value_operand(data_retrieval_response.result),
    )


# wont be used
def convert_to_native_data_retrieval_response(
    data_retrieval_response: EthereumDataRetrievalResponse,
) -> Response:
    return Response(
        id=uuid.uuid4().hex,
        # generally this request id represents native request id and not ethereum request id
        request_id=str(data_retrieval_response.request_id),
        status=ResponseStatus(data_retrieval_response.status.value),
        result=convert_to_native_value_operand(data_retrieval_response.result),
    )


def convert_from_native_data_retrieval_response(
    ethereum_request_id: EthereumRequestID, response: Response
) -> EthereumDataRetrievalResponse:
    return EthereumDataRetrievalResponse(
        status=convert_from_native_response_status(response.status),
        request_id=ethereum_request_id,
        result=convert_from_native_value_operand(response.result),
    )


SolidityDataStoreRequest = Tuple[
    SolidityValueOperand, int, int, int, int, int, Any, Any
]


@dataclass(frozen=True, slots=True)
class EthereumDataStoreRequest:
    operand: EthereumValueOperand
    payment: Wei
    acceptance_callback_gas: Wei
    acceptance_callback_payment: Wei
    submission_callback_gas: Wei
    submission_callback_payment: Wei
    # callback funcs acceptance callback and submission callback are not required here
    acceptance_callback: Any
    submission_callback: Any


def encode_to_python_data_store_request(
    data_store_request: SolidityDataStoreRequest,
) -> EthereumDataStoreRequest:
    return EthereumDataStoreRequest(
        operand=encode_to_python_value_operand(data_store_request[0]),
        payment=Wei(data_store_request[1]),
        acceptance_callback_gas=Wei(data_store_request[2]),
        acceptance_callback_payment=Wei(data_store_request[3]),
        submission_callback_gas=Wei(data_store_request[4]),
        submission_callback_payment=Wei(data_store_request[5]),
        acceptance_callback=data_store_request[6],
        submission_callback=data_store_request[7],
    )


def encode_to_solidity_data_store_request(
    data_store_request: EthereumDataStoreRequest,
) -> SolidityDataStoreRequest:
    return (
        encode_to_solidity_value_operand(data_store_request.operand),
        int(data_store_request.payment),
        int(data_store_request.acceptance_callback_gas),
        int(data_store_request.acceptance_callback_payment),
        int(data_store_request.submission_callback_gas),
        int(data_store_request.submission_callback_payment),
        data_store_request.acceptance_callback,
        data_store_request.submission_callback,
    )


def convert_to_native_data_store_request(
    data_store_request: EthereumDataStoreRequest,
) -> Request:
    return Request(
        id=uuid.uuid4().hex,
        operation=Operation.STORE,
        op1=Operand(
            data_type=convert_to_native_data_type(data_store_request.operand.data_type),
            location=OperandLocation.VALUE,
            encryption_scheme=convert_to_native_operand_encryption_scheme(
                data_store_request.operand.encryption_scheme
            ),
            data=data_store_request.operand.data,
        ),
        op2=Operand(
            data_type=DataType.BIT,
            location=OperandLocation.VALUE,
            encryption_scheme=OperandEncryptionScheme.NONE,
            data=b"",
        ),
    )


# wont be used
def convert_from_native_data_store_request(
    request: Request,
) -> EthereumDataStoreRequest:
    if request.operation != Operation.STORE:
        raise ValueError("Invalid operation type")

    if request.op1.location != OperandLocation.VALUE:
        raise ValueError("Invalid operand location type")

    return EthereumDataStoreRequest(
        operand=convert_from_native_value_operand(request.op1),
        # this makes the function not callable
        payment=Wei(0),
        acceptance_callback_gas=Wei(0),
        acceptance_callback_payment=Wei(0),
        submission_callback_gas=Wei(0),
        submission_callback_payment=Wei(0),
        # this might cause an issue as these are callback functions and not none
        # but currently we never abi encode this so it should be fine
        acceptance_callback=None,
        submission_callback=None,
    )


SolidityDataStoreResponse = Tuple[
    SolidityResponseStatus, EthereumRequestID, EthereumDataKey
]


@dataclass(frozen=True, slots=True)
class EthereumDataStoreResponse:
    status: EthereumResponseStatus
    request_id: EthereumRequestID
    key: EthereumDataKey


def encode_to_python_data_store_response(
    data_store_response: SolidityDataStoreResponse,
) -> EthereumDataStoreResponse:
    return EthereumDataStoreResponse(
        status=encode_to_python_response_status(data_store_response[0]),
        request_id=data_store_response[1],
        key=data_store_response[2],
    )


def encode_to_solidity_data_store_response(
    data_store_response: EthereumDataStoreResponse,
) -> SolidityDataStoreResponse:
    return (
        encode_to_solidity_response_status(data_store_response.status),
        data_store_response.request_id,
        data_store_response.key,
    )


# wont be used
def convert_to_native_data_store_response(
    data_store_response: EthereumDataStoreResponse,
) -> Response:
    return Response(
        id=uuid.uuid4().hex,
        # generally this request id represents native request id and not ethereum request id
        request_id=str(data_store_response.request_id),
        status=ResponseStatus(data_store_response.status.value),
        result=Operand(
            data_type=DataType.BIT,
            location=OperandLocation.VALUE,
            encryption_scheme=OperandEncryptionScheme.NONE,
            data=bytes(data_store_response.key),
        ),
    )


def convert_from_native_data_store_response(
    ethereum_request_id: EthereumRequestID, response: Response
) -> EthereumDataStoreResponse:
    if response.result is None:
        raise ValueError("Invalid response data")
    return EthereumDataStoreResponse(
        status=convert_from_native_response_status(response.status),
        request_id=ethereum_request_id,
        key=int.from_bytes(response.result.data, "big"),
    )


SolidityRequestType = int


class EthereumRequestType(Enum):
    OPERATION = 0
    DATA_RETRIEVAL = 1
    DATA_STORE = 2


def encode_to_python_request_type(
    request_type: SolidityRequestType,
) -> EthereumRequestType:
    return EthereumRequestType(request_type)


def encode_to_solidity_request_type(
    request_type: EthereumRequestType,
) -> SolidityRequestType:
    return request_type.value


SolidityNewRequestEvent = Tuple[EthereumRequestID, SolidityRequestType]


@dataclass(frozen=True, slots=True)
class EthereumNewRequestEvent:
    request_id: EthereumRequestID
    request_type: EthereumRequestType


def encode_to_python_new_request_event(
    new_request_event: SolidityNewRequestEvent,
) -> EthereumNewRequestEvent:
    return EthereumNewRequestEvent(
        request_id=new_request_event[0],
        request_type=encode_to_python_request_type(new_request_event[1]),
    )


def encode_to_solidity_new_request_event(
    new_request_event: EthereumNewRequestEvent,
) -> SolidityNewRequestEvent:
    return (
        new_request_event.request_id,
        encode_to_solidity_request_type(new_request_event.request_type),
    )


SolidityRequestAcceptedEvent = Tuple[EthereumRequestID]


@dataclass(frozen=True, slots=True)
class EthereumRequestAcceptedEvent:
    request_id: EthereumRequestID


def encode_to_python_request_accepted_event(
    request_accepted_event: SolidityRequestAcceptedEvent,
) -> EthereumRequestAcceptedEvent:
    return EthereumRequestAcceptedEvent(
        request_id=request_accepted_event[0],
    )


def encode_to_solidity_request_accepted_event(
    request_accepted_event: EthereumRequestAcceptedEvent,
) -> SolidityRequestAcceptedEvent:
    return (request_accepted_event.request_id,)


SolidityRequestProcessedEvent = Tuple[EthereumRequestID]


@dataclass(frozen=True, slots=True)
class EthereumRequestProcessedEvent:
    request_id: EthereumRequestID


def encode_to_python_request_processed_event(
    request_processed_event: SolidityRequestProcessedEvent,
) -> EthereumRequestProcessedEvent:
    return EthereumRequestProcessedEvent(
        request_id=request_processed_event[0],
    )


def encode_to_solidity_request_processed_event(
    request_processed_event: EthereumRequestProcessedEvent,
) -> SolidityRequestProcessedEvent:
    return (request_processed_event.request_id,)


@dataclass(frozen=True, slots=True)
class EthereumRequestWithPaymentInfoAndEthrereumRequestID:
    request: EthereumRequest
    payment: Wei
    requestee: Address
    ethereum_request_id: EthereumRequestID


@dataclass(frozen=True, slots=True)
class EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID:
    request: EthereumDataRetrievalRequest
    payment: Wei
    requestee: Address
    ethereum_request_id: EthereumRequestID


@dataclass(frozen=True, slots=True)
class EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID:
    request: EthereumDataStoreRequest
    payment: Wei
    requestee: Address
    ethereum_request_id: EthereumRequestID


async def retrieve_request_for_new_request_event(
    contract: AsyncContract,
    new_request_event: EthereumNewRequestEvent,
    timeout: float = 1,
) -> (
    EthereumRequestWithPaymentInfoAndEthrereumRequestID
    | EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID
    | EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID
):
    try:
        if new_request_event.request_type == EthereumRequestType.OPERATION:
            req = await asyncio.wait_for(
                contract.functions.pending_requests(
                    new_request_event.request_id
                ).call(),
                timeout,
            )

            try:
                return EthereumRequestWithPaymentInfoAndEthrereumRequestID(
                    request=encode_to_python_request(req[0]),
                    payment=Wei(req[1]),
                    requestee=Address(req[2]),
                    ethereum_request_id=new_request_event.request_id,
                )
            except Exception as e:
                raise ValueError(f"Error while converting request: {e}")
        elif new_request_event.request_type == EthereumRequestType.DATA_RETRIEVAL:
            req = await asyncio.wait_for(
                contract.functions.pending_data_requests(
                    new_request_event.request_id
                ).call(),
                timeout,
            )

            try:
                return EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID(
                    request=encode_to_python_data_retrieval_request(req[0]),
                    payment=Wei(req[1]),
                    requestee=Address(req[2]),
                    ethereum_request_id=new_request_event.request_id,
                )
            except Exception as e:
                raise ValueError(f"Error while converting request: {e}")

        elif new_request_event.request_type == EthereumRequestType.DATA_STORE:
            req = await asyncio.wait_for(
                contract.functions.pending_data_store_requests(
                    new_request_event.request_id
                ).call(),
                timeout,
            )

            try:
                return EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID(
                    request=encode_to_python_data_store_request(req[0]),
                    payment=Wei(req[1]),
                    requestee=Address(req[2]),
                    ethereum_request_id=new_request_event.request_id,
                )
            except Exception as e:
                raise ValueError(f"Error while converting request: {e}")
        else:
            raise ValueError("Invalid request type")
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while retrieving request: {e}")
    except Exception as e:
        raise ValueError(f"Error while retrieving request: {e}")


async def retrieve_requests_for_new_request_events(
    contract: AsyncContract,
    new_request_events: List[EthereumNewRequestEvent],
    timeout: float = 1,
) -> List[
    EthereumRequestWithPaymentInfoAndEthrereumRequestID
    | EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID
    | EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID
]:
    requests = []
    for event in new_request_events:
        requests.append(
            await retrieve_request_for_new_request_event(contract, event, timeout)
        )
    return requests


def convert_to_gwei(wei: Wei) -> int:
    return int(wei / 10**9)


BASE_GAS_WEI = Wei(62000 * 10**9)


async def submit_response(
    contract: AsyncContract,
    ethereum_request: EthereumRequestWithPaymentInfoAndEthrereumRequestID,
    response: Response,
    timeout: float = 1,
) -> None:
    try:
        required_gas_for_callback = Wei(
            ethereum_request.request.acceptance_callback_gas + BASE_GAS_WEI
        )
        if response.status != ResponseStatus.ACCEPTED:
            required_gas_for_callback = Wei(
                ethereum_request.request.submission_callback_gas + BASE_GAS_WEI
            )
        required_gas_for_callback_int = convert_to_gwei(required_gas_for_callback)
        required_payment = ethereum_request.request.acceptance_callback_payment
        if response.status != ResponseStatus.ACCEPTED:
            required_payment = ethereum_request.request.submission_callback_payment
        await asyncio.wait_for(
            contract.functions.submitResponse(
                encode_to_solidity_response(
                    convert_from_native_response(
                        ethereum_request.ethereum_request_id, response
                    )
                )
            ).transact(
                {
                    # "value": required_payment,
                    "gas": required_gas_for_callback_int,
                }
            ),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while submitting response: {e}")
    except Exception as e:
        raise ValueError(f"Error while submitting response: {e}")


async def submit_data_retrieval_response(
    contract: AsyncContract,
    ethereum_data_retrieval_request: EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID,
    response: Response,
    timeout: float = 1,
) -> None:
    try:
        await asyncio.wait_for(
            contract.functions.submitDataRetrievalResponse(
                encode_to_solidity_data_retrieval_response(
                    convert_from_native_data_retrieval_response(
                        ethereum_data_retrieval_request.ethereum_request_id, response
                    )
                )
            ).transact(
                {
                    # "value": ethereum_data_retrieval_request.request.callback_payment,
                    "gas": convert_to_gwei(
                        Wei(
                            ethereum_data_retrieval_request.request.callback_gas
                            + BASE_GAS_WEI
                        )
                    ),
                }
            ),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while submitting data retrieval response: {e}")
    except Exception as e:
        raise ValueError(f"Error while submitting data retrieval response: {e}")


async def submit_data_store_response(
    contract: AsyncContract,
    ethereum_data_store_request: EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
    response: Response,
    timeout: float = 1,
) -> None:
    required_gas_for_callback = Wei(
        ethereum_data_store_request.request.acceptance_callback_gas + BASE_GAS_WEI
    )
    if response.status != ResponseStatus.ACCEPTED:
        required_gas_for_callback = Wei(
            ethereum_data_store_request.request.submission_callback_gas + BASE_GAS_WEI
        )
    required_gas_for_callback_int = convert_to_gwei(required_gas_for_callback)
    required_payment = ethereum_data_store_request.request.acceptance_callback_payment
    if response.status != ResponseStatus.ACCEPTED:
        required_payment = (
            ethereum_data_store_request.request.submission_callback_payment
        )
    try:
        await asyncio.wait_for(
            contract.functions.submitDataStoreResponse(
                encode_to_solidity_data_store_response(
                    convert_from_native_data_store_response(
                        ethereum_data_store_request.ethereum_request_id, response
                    )
                )
            ).transact(
                {
                    # "value": required_payment,
                    "gas": required_gas_for_callback_int,
                }
            ),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while submitting data store response: {e}")
    except Exception as e:
        raise ValueError(f"Error while submitting data store response: {e}")


async def set_price(
    contract: AsyncContract,
    operation: EthereumOperation,
    price: Wei,
    timeout: float = 1,
) -> None:
    try:
        await asyncio.wait_for(
            contract.functions.setPrice(
                encode_to_solidity_operation(operation), price
            ).transact(),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while setting price: {e}")
    except Exception as e:
        raise ValueError(f"Error while setting price: {e}")


async def set_decryption_price(
    contract: AsyncContract,
    price: Wei,
    timeout: float = 1,
) -> None:
    try:
        await asyncio.wait_for(
            contract.functions.setDecryptionPrice(price).transact(),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while setting decryption price: {e}")
    except Exception as e:
        raise ValueError(f"Error while setting decryption price: {e}")


async def verify_abi(contract: AsyncContract) -> None:
    # verify contract abi
    # improve this
    try:
        required_functions = [
            "pending_requests",
            "pending_data_requests",
            "operation_cost",
            "decryption_cost",
            "submitResponse",
            "submitDataRetrievalResponse",
            "setPrice",
            "setDecryptionPrice",
        ]
        for func in required_functions:
            if not hasattr(contract.functions, func):
                raise ValueError(f"Function {func} not found in contract")
    except Exception as e:
        raise ValueError(f"Error verifying contract abi: {e}")


async def set_prices(
    contract: AsyncContract,
    operation_prices: Dict[EthereumOperation, Wei],
    decryption_price: Wei,
    store_price: Wei,
    timeout: float = 1,
) -> None:
    try:
        for operation, price in operation_prices.items():
            await asyncio.wait_for(
                contract.functions.setPrice(
                    encode_to_solidity_operation(operation), price
                ).transact(),
                timeout,
            )
        await asyncio.wait_for(
            contract.functions.setDecryptionPrice(decryption_price).transact(),
            timeout,
        )
        await asyncio.wait_for(
            contract.functions.setDataStorePrice(store_price).transact(),
            timeout,
        )
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while setting prices: {e}")
    except Exception as e:
        raise ValueError(f"Error while setting prices: {e}")


async def get_new_request_events_filter(
    contract: AsyncContract,
) -> Any:
    return await contract.events.NewRequest.create_filter(from_block="latest")


async def get_new_request_events(
    event_filter: Any,
    callback: Callable[[List[EthereumNewRequestEvent]], Awaitable[None]],
    timeout: float = 1,
) -> None:
    # save the events, if a the callback throws then those events are nopt considered used and are still new
    try:
        events = await asyncio.wait_for(event_filter.get_new_entries(), timeout)
        new_request_events = []
        for event in events:
            try:
                if "request_id" not in event.args or not isinstance(
                    event.args.request_id, EthereumRequestID
                ):
                    continue
                new_request_events.append(
                    EthereumNewRequestEvent(
                        request_id=EthereumRequestID(event.args.request_id),
                        # request_type=event.args.request_type,
                        request_type=encode_to_python_request_type(
                            event.args.request_type
                        ),
                    )
                )
            except Exception as e:
                print(f"Error while converting event: {e}")
                pass
        await callback(new_request_events)
    except asyncio.TimeoutError as e:
        raise ValueError(f"Timeout while waiting for new request event: {e}")
    except Exception as e:
        raise ValueError(f"Error while waiting for new request event: {e}")


class EthereumClientNetwork(IClientNetwork):
    __slots__ = (
        "_config",
        "_fetched_requests",
        "_request_queue",
        "_response_queue",
        "_exit_signal",
        "_request_fetcher_thread",
        "_response_sender_thread",
    )

    _config: EthereumClientConfig
    _fetched_requests: Dict[
        str,
        EthereumRequestWithPaymentInfoAndEthrereumRequestID
        | EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID
        | EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
    ]
    _request_queue: Queue[Request]
    _response_queue: Queue[Response]
    _exit_signal: Event
    _response_sender_thread: Thread
    _request_fetcher_thread: Thread

    def __init__(self, config: EthereumClientConfig):
        super().__init__("ethereum")
        self._config = config
        self._init()

    @override
    def run(self) -> None:
        self._request_fetcher_thread.start()
        self._response_sender_thread.start()

    @override
    def stop(self) -> None:
        self._exit_signal.set()
        self._request_fetcher_thread.join()
        self._response_sender_thread.join()
        print("EthereumClientNetwork stopped")

    @override
    def request_available(self) -> bool:
        return not self._request_queue.empty()

    @override
    def get_request(self):
        return self._request_queue.get()

    @override
    def put_response(self, response: Response):
        self._response_queue.put(response)

    def _init(self) -> None:
        self._fetched_requests = {}
        self._request_queue = Queue()
        self._response_queue = Queue()
        self._exit_signal = Event()
        self._exit_signal.clear()
        self._request_fetcher_thread = Thread(
            target=self._wrap_async_function,
            args=(self._request_fetcher, self._fetched_requests, self._request_queue),
            daemon=True,
        )
        self._response_sender_thread = Thread(
            target=self._wrap_async_function,
            args=(
                self._response_sender,
                self._fetched_requests,
                self._request_queue,
                self._response_queue,
            ),
            daemon=True,
        )

    def _read_abi(self, file_path: str) -> Any:
        abi: str | None = None
        try:
            with open(file_path, mode="r") as f:
                abi = f.read()
        except FileNotFoundError as e:
            raise ValueError(f"Contract ABI file not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error reading contract ABI file: {e}")

        if not abi:
            raise ValueError("Contract ABI file is empty")

        return json.loads(abi)

    async def _init_contract(self) -> AsyncContract:
        web3 = AsyncWeb3(WebSocketProvider(self._config.provider))
        await web3.provider.connect()
        if not (await web3.is_connected()):
            raise ValueError(
                f"Unable to connect to WebSocket provider at {self._config.provider}"
            )
        web3.middleware_onion.inject(
            SignAndSendRawMiddlewareBuilder.build(
                self._config.owner_account_private_key
            ),
            layer=0,
        )
        contract = web3.eth.contract(
            address=self._config.contract_address,  # type: ignore
            abi=self._read_abi(self._config.contract_abi_file_path),
        )
        await verify_abi(contract)
        return contract

    async def _get_price(self) -> Tuple[Dict[EthereumOperation, Wei], Wei, Wei]:
        return (
            {
                EthereumOperation.ADD: Wei(5),
                EthereumOperation.SUB: Wei(5),
                EthereumOperation.LT: Wei(5),
                EthereumOperation.GT: Wei(5),
                EthereumOperation.EQ: Wei(5),
                EthereumOperation.LTEQ: Wei(5),
                EthereumOperation.GTEQ: Wei(5),
                EthereumOperation.NAND: Wei(5),
            },
            Wei(5),
            Wei(5),
        )

    async def _request_fetcher(
        self,
        fetched_requests: Dict[
            str,
            EthereumRequestWithPaymentInfoAndEthrereumRequestID
            | EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID
            | EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
        ],
        request_queue: Queue[Request],
    ) -> None:
        contract = await self._init_contract()
        await set_prices(contract, *await self._get_price())

        async def putter(events):
            # this can block for large time ,the timeout is on each fetch
            requests = await retrieve_requests_for_new_request_events(contract, events)
            for request in requests:
                # native_req = convert_to_native_request(request.request)
                if isinstance(
                    request, EthereumRequestWithPaymentInfoAndEthrereumRequestID
                ):
                    native_req = convert_to_native_request(request.request)
                elif isinstance(
                    request,
                    EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID,
                ):
                    native_req = convert_to_native_data_retrieval_request(
                        request.request
                    )
                elif isinstance(
                    request,
                    EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
                ):
                    native_req = convert_to_native_data_store_request(request.request)
                else:
                    raise ValueError("Invalid request type")
                fetched_requests[native_req.id] = request
                request_queue.put(native_req)

        event_filter = await get_new_request_events_filter(contract)
        while not self._exit_signal.is_set():
            try:
                await get_new_request_events(
                    event_filter,
                    putter,
                )
            except ValueError as e:
                print(f"Error while fetching request: {e}. Retrying in 5 second")
                await asyncio.sleep(4)
            finally:
                await asyncio.sleep(1)

    async def _response_sender(
        self,
        fetched_requests: Dict[
            str,
            EthereumRequestWithPaymentInfoAndEthrereumRequestID
            | EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID
            | EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
        ],
        request_queue: Queue[Request],
        response_queue: Queue[Response],
    ) -> None:
        contract = await self._init_contract()

        response_queue.put(None)  # type: ignore
        while not self._exit_signal.is_set():
            try:
                for response in iter(response_queue.get, None):  # type: ignore
                    if response.request_id not in fetched_requests:
                        print(
                            f"Response for request {response.request_id} not found in fetched requests"
                        )
                        continue

                    request = fetched_requests[response.request_id]
                    if isinstance(
                        request,
                        EthereumRequestWithPaymentInfoAndEthrereumRequestID,
                    ):
                        await submit_response(
                            contract,
                            request,
                            response,
                        )
                    elif isinstance(
                        request,
                        EthereumDataRetrievalRequestWithPaymentInfoAndEthrereumRequestID,
                    ):
                        if response.status == ResponseStatus.ACCEPTED:
                            continue
                        await submit_data_retrieval_response(
                            contract,
                            request,
                            response,
                        )
                    elif isinstance(
                        request,
                        EthereumDataStoreRequestWithPaymentInfoAndEthrereumRequestID,
                    ):
                        await submit_data_store_response(
                            contract,
                            request,
                            response,
                        )
                    else:
                        raise ValueError("Invalid request type")

                    if response.status != ResponseStatus.ACCEPTED:
                        fetched_requests.pop(response.request_id)
                self._response_queue.put(None)  # type: ignore
            except ValueError as e:
                print(f"Error while sending response: {e}")
            finally:
                await asyncio.sleep(0.1)

    def _wrap_async_function(self, func, *args):
        asyncio.run(func(*args))

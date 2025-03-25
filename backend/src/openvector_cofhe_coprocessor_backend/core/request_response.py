from __future__ import annotations

from enum import Enum
from dataclasses import dataclass


class DataType(Enum):
    BIT = "bit"
    UINT32 = "uint32"


class OperandLocation(Enum):
    STORAGE_KEY = "storage_key"
    VALUE = "value"


class OperandEncryptionScheme(Enum):
    NONE = "none"
    CLHSM2k = "clhsm2k"
    RSA = "rsa"


@dataclass(frozen=True, slots=True)
class Operand:
    # for retrieve operation, this is ignored
    data_type: DataType
    # for retrieve and retrieve_reencrypt operation, this must be set to STORAGE_KEY
    location: OperandLocation
    # for retrieve_reencrypt operation, this represents the final required scheme
    # for retrieve operation, this is ignored
    encryption_scheme: OperandEncryptionScheme
    # for retrieve_reencrypt operation, this represents the storage key and other data such key for reencryption
    # the first 128 bits represent the storage key and the rest represent the data
    data: bytes


class Operation(Enum):
    ADD = "add"
    SUB = "sub"
    LT = "lt"
    GT = "gt"
    EQ = "eq"
    LTEQ = "lteq"
    GTEQ = "gteq"
    NAND = "nand"
    RETRIEVE = "retrieve"
    STORE = "store"
    RETRIEVE_REENCRYPT = "retrieve_reencrypt"


@dataclass(frozen=True, slots=True)
class Request:
    """For data retrieval and store request op2 wont be considered"""

    id: str
    operation: Operation
    op1: Operand
    op2: Operand


class ResponseStatus(Enum):
    ACCEPTED = "accepted"
    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_OPERATION = "invalid_operation"
    INSUFFICIENT_BALANCE = "insufficient_balance"
    INVALID_DATA_TYPE = "invalid_data_type"
    UNKNOWN_DATA_STORAGE_KEY = "unknown_data_storage_key"
    INVALID_ENCRYPTION_SCHEME = "invalid_encryption_scheme"


@dataclass(frozen=True, slots=True)
class Response:
    id: str
    request_id: str
    status: ResponseStatus
    result: Operand | None
    # for now represents the response id of the acceptance response
    correlation_response_id: str = ""

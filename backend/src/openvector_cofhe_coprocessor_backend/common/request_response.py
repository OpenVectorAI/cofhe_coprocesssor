from __future__ import annotations

from base64 import b64decode, b64encode
import binascii
from enum import StrEnum
from typing import Any, List

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DataType(StrEnum):
    SINGLE = "single"
    UINT32 = "uint32"
    REENCRYPTION_KEY = "reencryption_key"


class OperandLocation(StrEnum):
    STORAGE_KEY = "storage_key"
    VALUE = "value"


class OperandEncryptionScheme(StrEnum):
    NONE = "none"
    CLHSM2k = "clhsm2k"
    RSA = "rsa"


def decode_base64_bytes_field(value: Any, field_name_for_error: str) -> bytes:
    if isinstance(value, str):
        try:
            return b64decode(value.encode("ascii"))
        except (binascii.Error, ValueError) as e:
            raise ValueError(
                f"Field '{field_name_for_error}' has invalid base64 data: {e}"
            )
    elif isinstance(value, bytes):
        return value
    raise TypeError(
        f"Field '{field_name_for_error}' must be a base64 encoded string or bytes, "
        f"received type {type(value).__name__}"
    )


class Operand(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        json_encoders={
            bytes: lambda v: b64encode(v).decode("ascii"),
        },
    )
    # for retrieve operation, this is ignored
    data_type: DataType
    # for retrieve and retrieve_reencrypt operation, this must be set to STORAGE_KEY
    location: OperandLocation
    # for retrieve_reencrypt operation, this represents the final required scheme
    # for retrieve operation, this is ignored
    encryption_scheme: OperandEncryptionScheme
    data: bytes

    @field_validator("data", mode="before")
    @classmethod
    def validate_data(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "data")


class Operation(StrEnum):
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


# Currently acl only supports eth account based authentication
# and authorization part is fixed, anyone can compute on key,
# but only allowed(owner and others) can reencrypt and decrypt the data
# When computing on already available keys the acl is intersection of all
# acls for those objects
# Later we can generalize it to support any kind of acl
# The eth client network sets the verified origin with data provided by cofhe executor contract
# and the web2 client network uses signature verfication on particular request types to set the verified origin
# the storage format is List[bytes] where the first element is the owner of the storage key
# and the rest are the acl keys that can access the storage key
# the first is owner, others can reencrypt and decrypt the data


class Request(BaseModel):
    """For data retrieval and store request op2 wont be considered
    For retrieve_reencrypt request, op2 will be considered as the public key
    """

    model_config = ConfigDict(
        frozen=True,
        json_encoders={
            bytes: lambda v: b64encode(v).decode("ascii"),
        },
    )
    id: str
    operation: Operation
    op1: Operand
    op2: Operand
    verified_origin: bytes

    @field_validator("verified_origin", mode="before")
    @classmethod
    def validate_verified_origin(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "verified_origin")


class ResponseStatus(StrEnum):
    ACCEPTED = "accepted"
    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_OPERATION = "invalid_operation"
    INSUFFICIENT_BALANCE = "insufficient_balance"
    INVALID_DATA_TYPE = "invalid_data_type"
    UNKNOWN_DATA_STORAGE_KEY = "unknown_data_storage_key"
    INVALID_ENCRYPTION_SCHEME = "invalid_encryption_scheme"


class ResponseType(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        json_encoders={
            bytes: lambda v: b64encode(v).decode("ascii"),
        },
    )
    id: str
    request_id: str
    status: ResponseStatus
    # for now represents the response id of the acceptance response
    correlation_response_id: str | None = None


class Response(ResponseType):
    result: Operand | None


class ConfidentialCoinRequest(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        json_encoders={
            bytes: lambda v: b64encode(v).decode("ascii"),
        },
    )
    id: str
    is_mint_request: bool
    sender_balance_storage_key: bytes
    receiver_balance_storage_key: bytes
    amount: bytes | int
    consider_amount_negative: bool
    sender_balance_storage_key_acl: List[bytes] = Field(default_factory=list)
    receiver_balance_storage_key_acl: List[bytes] = Field(default_factory=list)

    @field_validator("sender_balance_storage_key", mode="before")
    @classmethod
    def validate_sender_balance_storage_key(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "sender_balance_storage_key")

    @field_validator("receiver_balance_storage_key", mode="before")
    @classmethod
    def validate_receiver_balance_storage_key(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "receiver_balance_storage_key")

    @field_validator("sender_balance_storage_key_acl", mode="before")
    @classmethod
    def validate_sender_balance_storage_key_acl(
        cls, value: List[bytes | str]
    ) -> List[bytes]:
        if not value:
            return []
        return [
            decode_base64_bytes_field(v, "sender_balance_storage_key_acl")
            for v in value
        ]

    @field_validator("receiver_balance_storage_key_acl", mode="before")
    @classmethod
    def validate_receiver_balance_storage_key_acl(
        cls, value: List[bytes | str]
    ) -> List[bytes]:
        if not value:
            return []
        return [
            decode_base64_bytes_field(v, "receiver_balance_storage_key_acl")
            for v in value
        ]

    @field_validator("amount", mode="before")
    @classmethod
    def validate_amount(cls, value: bytes | int) -> bytes | int:
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return decode_base64_bytes_field(value, "amount")
        elif isinstance(value, bytes):
            return decode_base64_bytes_field(value, "amount")
        elif isinstance(value, int):
            return value
        raise TypeError(
            f"Field 'amount' must be a base64 encoded string, bytes or an integer, "
            f"received type {type(value).__name__}"
        )


class ConfidentialCoinResponse(ResponseType):
    model_config = ConfigDict(
        frozen=True,
        json_encoders={
            bytes: lambda v: b64encode(v).decode("ascii"),
        },
    )

    success: bool
    # sender balance is total_supply in case of mint request
    sender_balance_storage_key: bytes
    receiver_balance_storage_key: bytes

    @field_validator("sender_balance_storage_key", mode="before")
    @classmethod
    def validate_sender_balance_storage_key(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "sender_balance_storage_key")

    @field_validator("receiver_balance_storage_key", mode="before")
    @classmethod
    def validate_receiver_balance_storage_key(cls, value: bytes | str) -> bytes:
        return decode_base64_bytes_field(value, "receiver_balance_storage_key")

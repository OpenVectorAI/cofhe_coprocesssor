from __future__ import annotations
from base64 import b64decode, b64encode
from datetime import datetime
import json
import os
from typing import Dict, List, Tuple

from openvector_cofhe_coprocessor_backend.common.logger import LogMessage, Logger
from typing_extensions import override
from abc import ABC, abstractmethod

from dataclasses import dataclass
from queue import Queue
from threading import Thread, Event
import asyncio
import uuid
import random

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from openvector_cofhe_coprocessor_backend.core.request_response import (
    Operation,
    DataType,
    OperandLocation,
    OperandEncryptionScheme,
    Operand,
    Request,
    Response,
    ResponseStatus,
    ConfidentialCoinRequest,
    ConfidentialCoinResponse,
)

from openvector_cofhe_coprocessor_backend.common.storage import Storage, FileStorage

from pycofhe.cryptosystems import CPUCryptoSystemCipherText as CipherText
from pycofhe.network import make_cpu_cryptosystem_client_node, CPUCryptoSystemClientNode
from pycofhe.network import (
    DataEncryptionType as PyCOFHEDataEncryptionType,
    DataType as PyCOFHEDataType,
    ComputeOperation as PyCOFHEComputeOperation,
    ComputeOperationType as PyCOFHEComputeOperationType,
    ComputeOperationOperand as PyCOFHEComputeOperationOperand,
    ComputeOperationInstance as PyCOFHEComputeOperationInstance,
    ComputeRequest as PyCOFHEComputeRequest,
    ComputeResponse as PyCOFHEComputeResponse,
    encrypt_bit as encrypt_single,
    decrypt_bit as decrypt_single,
    decrypt_bitwise,
    homomorphic_nand,
    homomorphic_or,
    homomorphic_add,
    homomorphic_sub,
    homomorphic_lt,
    homomorphic_eq,
    homomorphic_gt,
    serialize_bit as serialize_single,
    deserialize_bit as deserialize_single,
    serialize_bitwise,
    deserialize_bitwise,
    native_transfer_func,
)


class ICoreService(ABC):
    @abstractmethod
    def run(self) -> None:
        """Run the core service"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the core service"""
        pass

    @abstractmethod
    def submit_request(self, request: Request | ConfidentialCoinRequest) -> str:
        """Process the request"""
        pass

    @abstractmethod
    def response_available(self) -> bool:
        """Check the response"""
        pass

    @abstractmethod
    def get_response(self) -> Response | ConfidentialCoinResponse:
        """Get the response"""
        pass


@dataclass(frozen=True, slots=True)
class CoreServiceConfig:
    """Configuration for the core service"""

    client_node_ip: str
    client_node_port: str
    setup_node_ip: str
    setup_node_port: str
    cert_path: str
    storage_path: str
    storage_overwrite: bool


class CPUCryptoSystemClientNodeWrapper:
    __slots__ = (
        "_client_node",
        "_storage",
        "_logger",
        "_eagerly_evaluated_confidential_coin_request_responses",
    )

    _client_node: CPUCryptoSystemClientNode
    _storage: Storage
    _logger: Logger
    _eagerly_evaluated_confidential_coin_request_responses: Dict[
        str, ConfidentialCoinResponse
    ]

    def __init__(
        self,
        client_node: CPUCryptoSystemClientNode,
        storage: Storage,
        logger: Logger,
    ):
        self._client_node = client_node
        self._storage = storage
        self._logger = logger
        self._eagerly_evaluated_confidential_coin_request_responses = {}

    async def get_optimistic_result(self, request: Request) -> Operand:
        self._logger.debug(f"Optimistic evaluation for request {request.id}")
        return Operand(
            data_type=self._get_result_data_type(
                request.operation, request.op1.data_type, request.op2.data_type
            ),
            location=OperandLocation.STORAGE_KEY,
            encryption_scheme=self._get_result_encryption_scheme(
                request.operation,
                request.op1.encryption_scheme,
                request.op2.encryption_scheme,
            ),
            data=self._get_optimistic_storage_key(request),
        )

    async def process_request(
        self, accepted_response: Response, request: Request
    ) -> Response:
        # currently this is blocking as underlying cofhe cpp lib client is blocking
        self._logger.debug(f"Processing request {request.id}")
        try:
            if accepted_response.status != ResponseStatus.ACCEPTED:
                raise ValueError("Invalid response status")
            if request.operation == Operation.RETRIEVE:
                return await self._handle_retrieve(accepted_response, request)
            if request.operation == Operation.STORE:
                return await self._handle_store_request(accepted_response, request)
            if request.operation == Operation.RETRIEVE_REENCRYPT:
                return await self._handle_retrieve_reencrypt(accepted_response, request)

            return await self._handle_request(accepted_response, request)
        except NotImplementedError as e:
            self._logger.error(
                LogMessage(
                    message="Error processing request, operation not supported/implemented",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": str(accepted_response),
                        "error": str(e),
                    },
                )
            )
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.INVALID_OPERATION,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except KeyError as e:
            self._logger.error(
                LogMessage(
                    message="Error processing request, storage key not found",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": str(accepted_response),
                        "error": str(e),
                    },
                )
            )
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.UNKNOWN_DATA_STORAGE_KEY,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except ValueError as e:
            self._logger.error(
                LogMessage(
                    message="Error processing request, invalid operand",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": str(accepted_response),
                        "error": str(e),
                    },
                )
            )
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.INVALID_DATA_TYPE,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except Exception as e:
            self._logger.error(
                LogMessage(
                    message="Error processing request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": str(accepted_response),
                        "error": str(e),
                    },
                )
            )
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.FAILURE,
                result=None,
                correlation_response_id=accepted_response.id,
            )

    async def process_confidential_coin_request_optimistic(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        # todo optimistic evaluation
        if request.is_mint_request:
            return await self._process_mint_request(request, response_id)
        return await self._process_transfer_request(request, response_id)

    async def _process_transfer_request(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if request.is_mint_request:
            raise ValueError("Should not be a mint request")

        self._logger.debug(f"Processing transfer request {request.id}")

        sender_balance = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.STORAGE_KEY,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=request.sender_balance_storage_key,
            )
        )
        if not request.receiver_balance_storage_key or all(
            b == 0 for b in request.receiver_balance_storage_key
        ):
            receiver_balance: CipherText | List[CipherText] = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                0,
            )
        else:
            receiver_balance = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.STORAGE_KEY,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.receiver_balance_storage_key,
                )
            )

        amount = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=request.amount,
            )
        )
        if (
            not isinstance(sender_balance, CipherText)
            or not isinstance(receiver_balance, CipherText)
            or not isinstance(amount, CipherText)
        ):
            self._logger.error(
                LogMessage(
                    message="Invalid operand types for transfer request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_sender_balance_corrupted": str(
                            not isinstance(sender_balance, CipherText)
                        ),
                        "is_receiver_balance_corrupted": str(
                            not isinstance(receiver_balance, CipherText)
                        ),
                        "is_amount_corrupted": str(not isinstance(amount, CipherText)),
                        "sender_balance": str(sender_balance),
                        "receiver_balance": str(receiver_balance),
                        "amount": str(amount),
                    },
                )
            )
            raise ValueError("Invalid balance")

        start_time = datetime.now()
        sucess, new_balances = native_transfer_func(
            self._client_node, sender_balance, receiver_balance, amount
        )
        end_time = datetime.now()
        self._logger.debug(
            LogMessage(
                message="Transfer request processed",
                structured_log_message_data={
                    "request_id": request.id,
                    "success": str(sucess),
                    "new_balances": str(new_balances),
                    "processing_time": str(end_time - start_time),
                },
            )
        )
        correlation_response_id = response_id
        if not sucess:
            self._logger.debug(
                f"Transfer request failed {request.id} because of insufficient balance"
            )
            self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
                ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            )

            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        new_sender_balance = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            new_balances[0],
        )
        new_receiver_balance = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            new_balances[1],
        )

        new_sender_balance_storage_key = self._get_new_storage_key()
        new_receiver_balance_storage_key = self._get_new_storage_key()
        self._save_operand(new_sender_balance_storage_key, new_sender_balance)
        self._save_operand(new_receiver_balance_storage_key, new_receiver_balance)
        self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
            ConfidentialCoinResponse(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.SUCCESS,
                success=True,
                sender_balance_storage_key=new_sender_balance_storage_key,
                receiver_balance_storage_key=new_receiver_balance_storage_key,
                correlation_response_id=correlation_response_id,
            )
        )

        return ConfidentialCoinResponse(
            id=correlation_response_id,
            request_id=request.id,
            status=ResponseStatus.ACCEPTED,
            success=True,
            sender_balance_storage_key=new_sender_balance_storage_key,
            receiver_balance_storage_key=new_receiver_balance_storage_key,
        )

    async def _process_mint_request(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if not request.is_mint_request:
            raise ValueError("Should be a mint request")

        self._logger.debug(f"Processing mint request {request.id}")

        # if both sender and receiver balance storage keys are empty,
        # just store the new balance value in storage and return that as new
        # sender balance storage key and receiver balance storage key
        # if receiver balance storage key is empty, store the new value in storage
        # retrieve the current sender key operand, add the new value to it
        # now send these as new values
        # if reciever is not empty but sender is empty- this will never happen
        # if both are not empty, retrieve both, add the new value to both and store
        # the new values in storage and return the new storage keys

        correlation_response_id = response_id
        is_total_amount_zero = not request.sender_balance_storage_key or all(
            b == 0 for b in request.sender_balance_storage_key
        )
        is_minter_balance_zero = not request.receiver_balance_storage_key or all(
            b == 0 for b in request.receiver_balance_storage_key
        )
        if is_total_amount_zero and (not is_minter_balance_zero):
            self._logger.error(
                LogMessage(
                    message="Invalid mint request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_total_amount_zero": str(is_total_amount_zero),
                        "is_minter_balance_zero": str(is_minter_balance_zero),
                    },
                )
            )
            raise ValueError("Invalid mint request")

        if is_total_amount_zero and is_minter_balance_zero:
            new_total_amount = Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=request.amount,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            self._save_operand(new_total_amount_storage_key, new_total_amount)
            self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
                ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_total_amount_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=True,
                sender_balance_storage_key=new_total_amount_storage_key,
                receiver_balance_storage_key=new_total_amount_storage_key,
            )

        if (not is_total_amount_zero) and is_minter_balance_zero:
            current_total_amount = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.STORAGE_KEY,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.sender_balance_storage_key,
                )
            )
            mint_amount = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.VALUE,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.amount,
                )
            )
            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                self._handle_add(current_total_amount, mint_amount),
            )
            new_receiver_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                mint_amount,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_receiver_amount_storage_key = self._get_new_storage_key()
            self._save_operand(new_total_amount_storage_key, new_total_amount)
            self._save_operand(new_receiver_amount_storage_key, new_receiver_amount)
            self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
                ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_receiver_amount_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=True,
                sender_balance_storage_key=new_total_amount_storage_key,
                receiver_balance_storage_key=new_receiver_amount_storage_key,
            )

        if (not is_total_amount_zero) and (not is_minter_balance_zero):
            current_total_amount = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.STORAGE_KEY,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.sender_balance_storage_key,
                )
            )
            current_minter_amount = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.STORAGE_KEY,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.receiver_balance_storage_key,
                )
            )
            mint_amount = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.VALUE,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.amount,
                )
            )
            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                self._handle_add(current_total_amount, mint_amount),
            )
            new_minter_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                self._handle_add(current_minter_amount, mint_amount),
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_minter_amount_storage_key = self._get_new_storage_key()
            self._save_operand(new_total_amount_storage_key, new_total_amount)
            self._save_operand(new_minter_amount_storage_key, new_minter_amount)
            self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
                ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_minter_amount_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=True,
                sender_balance_storage_key=new_total_amount_storage_key,
                receiver_balance_storage_key=new_minter_amount_storage_key,
            )

        raise NotImplementedError("Should not reach here")

    async def process_confidential_coin_request(
        self,
        accepted_response: ConfidentialCoinResponse,
        request: ConfidentialCoinRequest,
    ) -> ConfidentialCoinResponse:
        if accepted_response.status != ResponseStatus.ACCEPTED:
            raise ValueError("Invalid response status")

        if (
            request.id
            not in self._eagerly_evaluated_confidential_coin_request_responses
        ):
            self._logger.error(
                LogMessage(
                    message="Invalid request id",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": str(accepted_response),
                    },
                )
            )
            raise ValueError("Invalid request id")

        return self._eagerly_evaluated_confidential_coin_request_responses.pop(
            request.id
        )

    async def _handle_retrieve(
        self, accepted_response: Response, request: Request
    ) -> Response:
        op1 = self._get_operand(request.op1.data)
        return Response(
            id=uuid.uuid4().hex,
            request_id=request.id,
            status=ResponseStatus.SUCCESS,
            result=op1,
            correlation_response_id=accepted_response.id,
        )

    async def _handle_retrieve_reencrypt(
        self, accepted_response: Response, request: Request
    ) -> Response:
        if request.op1.location != OperandLocation.STORAGE_KEY:
            raise ValueError("Invalid operand location")
        if (
            request.op1.encryption_scheme != OperandEncryptionScheme.NONE
            and request.op1.encryption_scheme != OperandEncryptionScheme.RSA
        ):
            raise ValueError("Invalid encryption scheme")

        op = self._get_operand(request.op1.data)
        opc = self._get_cofhe_operand(op)

        if request.op1.encryption_scheme == OperandEncryptionScheme.NONE:
            num = 0
            if op.data_type == DataType.UINT32:
                if not isinstance(opc, list):
                    raise ValueError("Invalid operand")
                num = decrypt_bitwise(self._client_node, opc)
            else:
                if not isinstance(opc, CipherText):
                    raise ValueError("Invalid operand")
                num = decrypt_single(self._client_node, opc)
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.SUCCESS,
                result=self._make_operand(
                    request.op1.data_type,
                    OperandLocation.VALUE,
                    OperandEncryptionScheme.NONE,
                    num.to_bytes(32, byteorder="big"),
                ),
                correlation_response_id=accepted_response.id,
            )

        if request.op1.encryption_scheme == OperandEncryptionScheme.RSA:
            if not isinstance(opc, CipherText):
                # bitwise encoded number reencryption not supported for now
                raise ValueError("Invalid operand")
            serialized_reencrytor_pub_key = request.op2.data
            if request.op2.location != OperandLocation.VALUE:
                oppub = self._get_operand(request.op2.data)
                serialized_reencrytor_pub_key = oppub.data

            reencrypted_data = self._reencrypt_ciphertext(
                self._client_node, opc, serialized_reencrytor_pub_key
            )
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.SUCCESS,
                result=self._make_operand(
                    request.op1.data_type,
                    OperandLocation.VALUE,
                    OperandEncryptionScheme.RSA,
                    reencrypted_data,
                ),
                correlation_response_id=accepted_response.id,
            )

        raise ValueError("Invalid encryption scheme")

    async def _handle_store_request(
        self, accepted_response: Response, request: Request
    ) -> Response:
        if accepted_response.result is None:
            raise ValueError("Invalid response")
        if request.op1.location != OperandLocation.VALUE:
            raise ValueError("Invalid operand location")
        if request.op1.encryption_scheme != OperandEncryptionScheme.CLHSM2k:
            if request.op1.data_type != DataType.REENCRYPTION_KEY:
                raise ValueError("Invalid encryption scheme")

        self._save_operand(self._get_storage_key(accepted_response.result), request.op1)
        return Response(
            id=uuid.uuid4().hex,
            request_id=request.id,
            status=ResponseStatus.SUCCESS,
            result=self._make_operand(
                request.op1.data_type,
                OperandLocation.STORAGE_KEY,
                request.op1.encryption_scheme,
                accepted_response.result.data,
            ),
            correlation_response_id=accepted_response.id,
        )

    async def _handle_request(
        self, accepted_response: Response, request: Request
    ) -> Response:
        if accepted_response.result is None:
            raise ValueError("Invalid response")
        op1_n = self._get_cofhe_operand(request.op1)
        op2_n = self._get_cofhe_operand(request.op2)
        result = None
        if request.operation == Operation.ADD:
            result = self._handle_add(op1_n, op2_n)
        elif request.operation == Operation.SUB:
            result = self._handle_sub(op1_n, op2_n)
        else:
            if isinstance(op1_n, CipherText) or isinstance(op2_n, CipherText):
                raise ValueError("Invalid operands")
            if request.operation == Operation.LT:
                result = self._handle_lt(op1_n, op2_n)
            elif request.operation == Operation.GT:
                result = self._handle_gt(op1_n, op2_n)
            elif request.operation == Operation.EQ:
                result = self._handle_eq(op1_n, op2_n)
            elif request.operation == Operation.LTEQ:
                result = self._handle_lteq(op1_n, op2_n)
            elif request.operation == Operation.GTEQ:
                result = self._handle_gteq(op1_n, op2_n)
            elif request.operation == Operation.NAND:
                result = self._handle_nand(op1_n, op2_n)
            else:
                raise NotImplementedError(
                    f"Operation {request.operation} not implemented"
                )

        result_p = self._make_operand(
            self._get_result_data_type(
                request.operation, request.op1.data_type, request.op2.data_type
            ),
            OperandLocation.VALUE,
            self._get_result_encryption_scheme(
                request.operation,
                request.op1.encryption_scheme,
                request.op2.encryption_scheme,
            ),
            result,
        )
        new_storage_key = self._get_storage_key(accepted_response.result)
        self._save_operand(new_storage_key, result_p)
        result_p = self._make_operand(
            result_p.data_type,
            OperandLocation.STORAGE_KEY,
            result_p.encryption_scheme,
            new_storage_key,
        )
        return Response(
            id=uuid.uuid4().hex,
            request_id=request.id,
            status=ResponseStatus.SUCCESS,
            result=result_p,
            correlation_response_id=accepted_response.id,
        )

    def _handle_add(
        self, op1: CipherText | List[CipherText], op2: CipherText | List[CipherText]
    ) -> CipherText | List[CipherText]:
        if isinstance(op1, CipherText) and isinstance(op2, CipherText):
            return self._client_node.cryptosystem.add_ciphertexts(
                self._client_node.network_encryption_key, op1, op2
            )
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_add(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_sub(
        self, op1: CipherText | List[CipherText], op2: CipherText | List[CipherText]
    ) -> CipherText | List[CipherText]:
        if isinstance(op1, CipherText) and isinstance(op2, CipherText):
            return self._client_node.cryptosystem.add_ciphertexts(
                self._client_node.network_encryption_key,
                op1,
                self._client_node.cryptosystem.negate_ciphertext(
                    self._client_node.network_encryption_key, op2
                ),
            )
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_sub(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_lt(self, op1: List[CipherText], op2: List[CipherText]) -> CipherText:
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_lt(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_gt(self, op1: List[CipherText], op2: List[CipherText]) -> CipherText:
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_gt(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_eq(self, op1: List[CipherText], op2: List[CipherText]) -> CipherText:
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_eq(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_lteq(self, op1: List[CipherText], op2: List[CipherText]) -> CipherText:
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_or(
                self._client_node,
                homomorphic_eq(self._client_node, op1, op2),
                homomorphic_lt(self._client_node, op1, op2),
            )
        raise ValueError("Invalid operands")

    def _handle_gteq(self, op1: List[CipherText], op2: List[CipherText]) -> CipherText:
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_or(
                self._client_node,
                homomorphic_eq(self._client_node, op1, op2),
                homomorphic_gt(self._client_node, op1, op2),
            )
        raise ValueError("Invalid operands")

    def _handle_nand(
        self, op1: CipherText | List[CipherText], op2: CipherText | List[CipherText]
    ) -> CipherText:
        if isinstance(op1, list) or isinstance(op2, list):
            raise ValueError("Invalid operands")
        return homomorphic_nand(self._client_node, op1, op2)

    def _reencrypt_ciphertext(
        self,
        client_node: CPUCryptoSystemClientNode,
        ciphertext: CipherText,
        serialized_reencrytor_pub_key: bytes,
    ) -> bytes:
        dop = PyCOFHEComputeOperationOperand(
            PyCOFHEDataType.SINGLE,
            PyCOFHEDataEncryptionType.CIPHERTEXT,
            serialize_single(client_node.cryptosystem, ciphertext),
        )
        pub_key_op = PyCOFHEComputeOperationOperand(
            PyCOFHEDataType.SINGLE,
            PyCOFHEDataEncryptionType.PLAINTEXT,
            serialized_reencrytor_pub_key,
        )
        dop_instance = PyCOFHEComputeOperationInstance(
            PyCOFHEComputeOperationType.BINARY,
            PyCOFHEComputeOperation.REENCRYPT,
            [dop, pub_key_op],
        )
        req = PyCOFHEComputeRequest(dop_instance)
        res = client_node.compute(req)

        return res.data_bytes

    def _get_cofhe_operand(self, operand: Operand) -> List[CipherText] | CipherText:
        data = operand.data
        if operand.location == OperandLocation.STORAGE_KEY:
            ret_op = self._get_operand(operand.data)
            data = ret_op.data
        return self._parse_serialized_operand_data(data, operand.data_type)

    def _parse_serialized_operand_data(
        self, data: bytes, data_type: DataType
    ) -> List[CipherText] | CipherText:
        if data_type == DataType.SINGLE:
            return deserialize_single(self._client_node.cryptosystem, data)
        if data_type == DataType.UINT32:
            return deserialize_bitwise(self._client_node.cryptosystem, data)
        raise ValueError(f"Invalid data type {data_type}")

    def _serialize_cofhe_operand_data(
        self, data: List[CipherText] | CipherText
    ) -> bytes:
        if isinstance(data, CipherText):
            return serialize_single(self._client_node.cryptosystem, data)
        if isinstance(data, list):
            return serialize_bitwise(self._client_node.cryptosystem, data)
        raise ValueError(f"Invalid data type {data}")

    def _get_operand(self, storage_key: bytes) -> Operand:
        storage_key_str = self._convert_bytes_to_storage_key(storage_key).hex()
        if self._storage.check(storage_key_str):
            return self._deserialize_operand(self._storage.get(storage_key_str))
        raise KeyError(f"Storage key {storage_key_str} not found")

    def _save_operand(self, key: bytes, op: Operand) -> None:
        key_str = key.hex()
        self._logger.debug(
            LogMessage(
                message="Saving operand",
                structured_log_message_data={
                    "key": key_str,
                    "operand": str(op),
                },
            )
        )
        self._storage.put(key_str, self._serialize_operand(op))

    def _serialize_operand(self, op: Operand) -> str:
        # The format is json, with operand properties as keys and values as values
        ser = self._make_operand_dict(op)
        ser["data"] = b64encode(ser["data"]).decode("ascii")
        return json.dumps(ser)

    def _deserialize_operand(self, data: str) -> Operand:
        loaded_obj = json.loads(data)
        loaded_obj["data"] = b64decode(loaded_obj["data"])
        return self._make_operand_from_dict(loaded_obj)

    def _make_operand(
        self,
        data_type: DataType,
        location: OperandLocation,
        encryption_scheme: OperandEncryptionScheme,
        data: bytes | CipherText | List[CipherText],
    ) -> Operand:
        if isinstance(data, CipherText) or isinstance(data, list):
            ac_data = self._serialize_cofhe_operand_data(data)
        else:
            ac_data = data
        return Operand(
            data_type=data_type,
            location=location,
            encryption_scheme=encryption_scheme,
            data=ac_data,
        )

    def _make_operand_dict(self, op: Operand) -> dict:
        return {
            "data_type": op.data_type.value,
            "location": op.location.value,
            "encryption_scheme": op.encryption_scheme.value,
            "data": op.data,
        }

    def _make_operand_from_dict(self, data: dict) -> Operand:
        if "data" not in data:
            raise ValueError("Invalid operand data")
        if "encryption_scheme" not in data:
            raise ValueError("Invalid operand encryption scheme")
        if "location" not in data:
            raise ValueError("Invalid operand location")
        if "data_type" not in data:
            raise ValueError("Invalid operand data type")
        return Operand(
            data_type=DataType(data["data_type"]),
            location=OperandLocation(data["location"]),
            encryption_scheme=OperandEncryptionScheme(data["encryption_scheme"]),
            data=data["data"],
        )

    def _get_optimistic_storage_key(self, request: Request) -> bytes:
        return self._get_new_storage_key()

    def _get_result_data_type(
        self, operation: Operation, data_type1: DataType, data_type2: DataType
    ) -> DataType:
        single_ops = [
            Operation.LT,
            Operation.GT,
            Operation.EQ,
            Operation.LTEQ,
            Operation.GTEQ,
            Operation.NAND,
        ]
        non_det_ops = [Operation.RETRIEVE]
        same_type_ops = [
            Operation.ADD,
            Operation.SUB,
            Operation.STORE,
            Operation.RETRIEVE_REENCRYPT,
        ]
        if operation in same_type_ops:
            return data_type1
        if operation in non_det_ops:
            return data_type1
        if operation in single_ops:
            return DataType.SINGLE
        raise NotImplementedError(f"Operation {operation} not implemented")

    def _get_result_encryption_scheme(
        self,
        operation: Operation,
        encryption_scheme1: OperandEncryptionScheme,
        encryption_scheme2: OperandEncryptionScheme,
    ) -> OperandEncryptionScheme:
        if operation == Operation.RETRIEVE:
            return encryption_scheme1
        if operation == Operation.STORE:
            return OperandEncryptionScheme.CLHSM2k
        if operation == Operation.RETRIEVE_REENCRYPT:
            return encryption_scheme1
        if encryption_scheme1 != encryption_scheme2:
            raise ValueError("Encryption schemes must be the same for now")
        return encryption_scheme1

    def _get_storage_key(self, operand: Operand) -> bytes:
        if operand.location != OperandLocation.STORAGE_KEY:
            raise ValueError("Invalid operand location")
        return self._convert_bytes_to_storage_key(operand.data)

    def _convert_bytes_to_storage_key(self, data: bytes) -> bytes:
        return b"\0" * (16 - len(data)) + data

    def _get_new_storage_key(self) -> bytes:
        return uuid.uuid4().bytes


@dataclass(frozen=True, slots=True)
class RequestWithResponseId:
    request: Request
    response_id: str


@dataclass(frozen=True, slots=True)
class ConfidentialCoinRequestWithResponseId:
    request: ConfidentialCoinRequest
    response_id: str


class CoreService(ICoreService):
    __slots__ = (
        "_client_node",
        "_config",
        "_request_queue",
        "_response_queue",
        "_exit_signal",
        "_worker_thread",
        "_logger",
    )

    _client_node: CPUCryptoSystemClientNodeWrapper
    _config: CoreServiceConfig
    _request_queue: Queue[RequestWithResponseId | ConfidentialCoinRequestWithResponseId]
    _response_queue: Queue[Response | ConfidentialCoinResponse]
    _exit_signal: Event
    _worker_thread: Thread
    _logger: Logger

    def __init__(self, config: CoreServiceConfig, logger: Logger):
        self._logger = logger
        self._client_node = CPUCryptoSystemClientNodeWrapper(
            self._get_client_node(config),
            self._get_storage(config),
            logger,
        )
        self._config = config
        self._request_queue = Queue()
        self._response_queue = Queue()
        self._exit_signal = Event()
        self._exit_signal.clear()
        self._worker_thread = Thread(
            target=self._wrap_async_function,
            args=(
                self._worker,
                self._client_node,
                self._request_queue,
                self._response_queue,
            ),
            daemon=True,
        )

    @override
    def run(self) -> None:
        self._logger.info("Starting core service")
        self._worker_thread.start()

    @override
    def stop(self) -> None:
        self._logger.info("Stopping core service")
        self._exit_signal.set()
        self._worker_thread.join()
        self._logger.info("Core service stopped")

    @override
    def submit_request(self, request: Request | ConfidentialCoinRequest) -> str:
        response_id = uuid.uuid4().hex
        if isinstance(request, Request):
            self._request_queue.put(
                RequestWithResponseId(request=request, response_id=response_id)
            )
        else:
            self._request_queue.put(
                ConfidentialCoinRequestWithResponseId(
                    request=request, response_id=response_id
                )
            )
        return response_id

    @override
    def response_available(self) -> bool:
        return not self._response_queue.empty()

    @override
    def get_response(self) -> Response | ConfidentialCoinResponse:
        return self._response_queue.get()

    def _get_client_node(self, config: CoreServiceConfig) -> CPUCryptoSystemClientNode:
        try:
            client_node = make_cpu_cryptosystem_client_node(
                config.client_node_ip,
                config.client_node_port,
                config.setup_node_ip,
                config.setup_node_port,
                config.cert_path,
            )
            self._logger.info(
                LogMessage(
                    message="Connected to client node",
                    structured_log_message_data={
                        "network_details": client_node.network_details.to_string()
                    },
                )
            )
            return client_node
        except Exception as e:
            self._logger.error(
                LogMessage(
                    message="Unable to connect to client node",
                    structured_log_message_data={
                        "client_node_ip": config.client_node_ip,
                        "client_node_port": config.client_node_port,
                        "setup_node_ip": config.setup_node_ip,
                        "setup_node_port": config.setup_node_port,
                        "cert_path": config.cert_path,
                        "error": str(e),
                    },
                )
            )
            raise ValueError(
                f"Unable to connect to client node at {config.client_node_ip}:{config.client_node_port}"
            ) from e

    def _get_storage(self, config: CoreServiceConfig) -> Storage:
        if os.path.exists(config.storage_path):
            try:
                self._logger.info(
                    LogMessage(
                        message="Storage path already exists, using same",
                        structured_log_message_data={
                            "storage_path": config.storage_path,
                        },
                    )
                )
                return FileStorage(config.storage_path)
            except Exception as e:
                self._logger.error(
                    LogMessage(
                        message="Unable to open the storage",
                        structured_log_message_data={
                            "storage_path": config.storage_path,
                            "error": str(e),
                        },
                    )
                )
                if not config.storage_overwrite:
                    raise ValueError(
                        f"The storage path cannot be used: {config.storage_path}. Please check the path and try again."
                    ) from e

        try:
            return FileStorage.create(config.storage_path, overwrite=True)
        except Exception as e:
            self._logger.error(
                LogMessage(
                    message="Unable to create the storage",
                    structured_log_message_data={
                        "storage_path": config.storage_path,
                        "error": str(e),
                    },
                )
            )
            raise ValueError(
                f"The storage path cannot be used: {config.storage_path}. Please check the path and try again."
            ) from e

    async def _worker(
        self,
        client_node: CPUCryptoSystemClientNodeWrapper,
        request_queue: Queue[
            RequestWithResponseId | ConfidentialCoinRequestWithResponseId
        ],
        response_queue: Queue[Response | ConfidentialCoinResponse],
    ) -> None:
        while not self._exit_signal.is_set():
            if not request_queue.empty():
                # only process one request at a time
                request = request_queue.get()
                if isinstance(request, RequestWithResponseId):
                    self._logger.debug(
                        LogMessage(
                            message="Processing request",
                            structured_log_message_data={
                                "request_id": request.request.id,
                                "request": str(request),
                            },
                        )
                    )
                else:
                    self._logger.debug(
                        LogMessage(
                            message="Processing confidential coin request",
                            structured_log_message_data={
                                "request_id": request.request.id,
                                "request": str(request),
                            },
                        )
                    )
                try:
                    if isinstance(request, ConfidentialCoinRequestWithResponseId):
                        accepted_response_t = (
                            await self._accept_confidential_coin_request(request)
                        )
                        response_queue.put(accepted_response_t)
                        if accepted_response_t.status != ResponseStatus.ACCEPTED:
                            continue
                        response_queue.put(
                            await client_node.process_confidential_coin_request(
                                accepted_response_t, request.request
                            )
                        )
                    else:
                        accepted_response_n = await self._accept_request(request)
                        response_queue.put(accepted_response_n)
                        if accepted_response_n.status != ResponseStatus.ACCEPTED:
                            continue
                        response_queue.put(
                            await client_node.process_request(
                                accepted_response_n, request.request
                            )
                        )
                except Exception as e:
                    self._logger.error(
                        LogMessage(
                            message="Error processing request",
                            structured_log_message_data={
                                "request_id": request.request.id,
                                "accepted_response": str(request),
                                "error": str(e),
                            },
                        )
                    )
                    if isinstance(request, ConfidentialCoinRequestWithResponseId):
                        response_queue.put(
                            ConfidentialCoinResponse(
                                id=request.response_id,
                                request_id=request.request.id,
                                status=ResponseStatus.FAILURE,
                                success=False,
                                sender_balance_storage_key=b"",
                                receiver_balance_storage_key=b"",
                                correlation_response_id=request.response_id,
                            )
                        )
                    else:
                        response_queue.put(
                            Response(
                                id=request.response_id,
                                request_id=request.request.id,
                                status=ResponseStatus.FAILURE,
                                result=None,
                                correlation_response_id=request.response_id,
                            )
                        )
            else:
                await asyncio.sleep(0.1)

    async def _accept_request(self, request: RequestWithResponseId) -> Response:
        self._logger.debug(
            LogMessage(
                message="Accepting request",
                structured_log_message_data={
                    "request_id": request.request.id,
                    "request": str(request),
                },
            )
        )
        return Response(
            id=request.response_id,
            request_id=request.request.id,
            status=ResponseStatus.ACCEPTED,
            result=await self._client_node.get_optimistic_result(request.request),
        )

    async def _accept_confidential_coin_request(
        self, request: ConfidentialCoinRequestWithResponseId
    ) -> ConfidentialCoinResponse:
        self._logger.debug(
            LogMessage(
                message="Accepting confidential coin request",
                structured_log_message_data={
                    "request_id": request.request.id,
                    "request": str(request),
                },
            )
        )
        return await self._client_node.process_confidential_coin_request_optimistic(
            request.request, request.response_id
        )

    def _wrap_async_function(self, func, *args, **kwargs) -> None:
        asyncio.run(func(*args, **kwargs))

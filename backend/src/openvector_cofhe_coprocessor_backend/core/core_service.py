from __future__ import annotations
from base64 import b64decode, b64encode
from datetime import datetime
import json
import os
from typing import Dict, List

from openvector_cofhe_coprocessor_backend.common.logger import LogMessage, Logger
from typing_extensions import override

from dataclasses import dataclass
from queue import Queue
from threading import Lock, Thread, Event
import asyncio
import uuid

from openvector_cofhe_coprocessor_backend.common.request_response import (
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

from openvector_cofhe_coprocessor_backend.core.storage import Storage, FileStorage

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
    encrypt_bit as encrypt_single,
    decrypt_bit as decrypt_single,
    encrypt_bitwise,
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
from openvector_cofhe_coprocessor_backend.core.core_service_interface import (
    ICoreService,
)


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
        "_eagerly_evaluated_confidential_coin_request_responses_lock",
        "_eagerly_evaluated_confidential_coin_request_responses",
    )

    _client_node: CPUCryptoSystemClientNode
    _storage: Storage
    _logger: Logger
    _eagerly_evaluated_confidential_coin_request_responses_lock: Lock
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
        self._eagerly_evaluated_confidential_coin_request_responses_lock = Lock()
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
            if request.use_tee:
                return await self._process_request_tee(accepted_response, request)
            if request.operation == Operation.RETRIEVE:
                return await self._handle_retrieve(accepted_response, request)
            if request.operation == Operation.STORE:
                return await self._handle_store_request(accepted_response, request)
            if request.operation == Operation.RETRIEVE_REENCRYPT:
                return await self._handle_retrieve_reencrypt(accepted_response, request)

            return await self._handle_request(accepted_response, request)
        except NotImplementedError as e:
            self._logger.debug(
                LogMessage(
                    message="Error processing request, operation not supported/implemented",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": accepted_response.model_dump_json(),
                        "error": e,
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
            self._logger.debug(
                LogMessage(
                    message="Error processing request, storage key not found",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": accepted_response.model_dump_json(),
                        "error": e,
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
            self._logger.debug(
                LogMessage(
                    message="Error processing request, invalid operand",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": accepted_response.model_dump_json(),
                        "error": e,
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
                        "accepted_response": accepted_response.model_dump_json(),
                        "error": e,
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
        start_time = datetime.now()
        if request.use_tee:
            request_type = (
                "TEE_" + "TRANSFER" if not request.is_mint_request else "TEE_MINT"
            )
            res = await self._process_confidential_coin_request_tee(
                request, response_id
            )
        elif request.is_mint_request:
            request_type = "MINT"
            res = await self._process_mint_request(request, response_id)
        else:
            request_type = "TRANSFER"
            res = await self._process_transfer_request(request, response_id)
        end_time = datetime.now()
        self._logger.debug(
            LogMessage(
                message="Confidential coin request processed",
                structured_log_message_data={
                    "request_id": request.id,
                    "success": res.success,
                    "status": res.status,
                    "processing_time": (end_time - start_time).microseconds,
                    "request_type": request_type,
                },
            )
        )
        return res

    def _encrypt_and_serialize(self, data: int) -> bytes:
        return serialize_single(
            self._client_node.cryptosystem,
            self._client_node.cryptosystem.encrypt(
                self._client_node.network_encryption_key,
                self._client_node.cryptosystem.make_plaintext(float(data)),
            ),
        )

    async def _process_transfer_request(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if request.is_mint_request:
            raise ValueError("Should not be a mint request")

        self._logger.debug(f"Processing transfer request {request.id}")

        if request.consider_amount_negative:
            self._logger.debug(
                LogMessage(
                    message="Invalid transfer request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "consider_amount_negative": request.consider_amount_negative,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=response_id,
                )
            return ConfidentialCoinResponse(
                id=response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        sender_balance = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.STORAGE_KEY,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=request.sender_balance_storage_key,
            )
        )
        receiver_not_registered = (not request.receiver_balance_storage_key) or all(
            b == 0 for b in request.receiver_balance_storage_key
        )
        if receiver_not_registered:
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
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
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
                        "is_sender_balance_corrupted": not isinstance(
                            sender_balance, CipherText
                        ),
                        "is_receiver_balance_corrupted": not isinstance(
                            receiver_balance, CipherText
                        ),
                        "is_amount_corrupted": not isinstance(amount, CipherText),
                        "sender_balance": (sender_balance),
                        "receiver_balance": (receiver_balance),
                        "amount": (amount),
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=response_id,
                )
            return ConfidentialCoinResponse(
                id=response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

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
                    "success": sucess,
                    "new_balances": [
                        b64encode(
                            serialize_single(
                                self._client_node.cryptosystem, new_balances[0]
                            )
                        ).decode("ascii"),
                        b64encode(
                            serialize_single(
                                self._client_node.cryptosystem, new_balances[1]
                            )
                        ).decode("ascii"),
                    ],
                    "processing_time": (end_time - start_time).microseconds,
                },
            )
        )
        correlation_response_id = response_id
        if not sucess:
            self._logger.debug(
                f"Transfer request failed {request.id} because of insufficient balance"
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
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
        self._save_operand(
            new_sender_balance_storage_key,
            new_sender_balance,
            self._get_acl_for_storage_key(request.sender_balance_storage_key),
        )
        self._save_operand(
            new_receiver_balance_storage_key,
            new_receiver_balance,
            (
                request.receiver_balance_storage_key_acl
                if receiver_not_registered
                else self._get_acl_for_storage_key(request.receiver_balance_storage_key)
            ),
        )
        with self._eagerly_evaluated_confidential_coin_request_responses_lock:
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
        if request.consider_amount_negative:
            return await self._handle_deduction_request(request, response_id)
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
            self._logger.debug(
                LogMessage(
                    message="Invalid mint request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_total_amount_zero": is_total_amount_zero,
                        "is_minter_balance_zero": is_minter_balance_zero,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_OPERATION,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        if is_total_amount_zero and is_minter_balance_zero:
            new_total_amount = Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_receiver_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                request.sender_balance_storage_key_acl,
            )
            self._save_operand(
                new_receiver_amount_storage_key,
                new_total_amount,
                request.receiver_balance_storage_key_acl,
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_receiver_amount_storage_key,
                    correlation_response_id=correlation_response_id,
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
                    data=(
                        request.amount
                        if isinstance(request.amount, bytes)
                        else self._encrypt_and_serialize(
                            request.amount,
                        )
                    ),
                )
            )
            start_time = datetime.now()
            add_res = self._handle_add(current_total_amount, mint_amount)
            end_time = datetime.now()
            self._logger.debug(
                LogMessage(
                    message="Mint request addition processed for case where minter balance is zero",
                    structured_log_message_data={
                        "request_id": request.id,
                        "processing_time": (end_time - start_time).microseconds,
                    },
                )
            )

            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                add_res,
            )
            new_receiver_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                mint_amount,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_receiver_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                self._get_acl_for_storage_key(
                    request.sender_balance_storage_key,
                ),
            )
            self._save_operand(
                new_receiver_amount_storage_key,
                new_receiver_amount,
                request.receiver_balance_storage_key_acl,
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_receiver_amount_storage_key,
                    correlation_response_id=correlation_response_id,
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
                    data=(
                        request.amount
                        if isinstance(request.amount, bytes)
                        else self._encrypt_and_serialize(
                            request.amount,
                        )
                    ),
                )
            )
            start_time = datetime.now()
            t_add_res = self._handle_add(current_total_amount, mint_amount)
            m_add_res = self._handle_add(current_minter_amount, mint_amount)
            end_time = datetime.now()
            self._logger.debug(
                LogMessage(
                    message="Mint request addition processed for case where both balances are non-zero",
                    structured_log_message_data={
                        "request_id": request.id,
                        "processing_time": (end_time - start_time).microseconds,
                    },
                )
            )
            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                t_add_res,
            )
            new_minter_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                m_add_res,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_minter_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                self._get_acl_for_storage_key(
                    request.sender_balance_storage_key,
                ),
            )
            self._save_operand(
                new_minter_amount_storage_key,
                new_minter_amount,
                self._get_acl_for_storage_key(
                    request.receiver_balance_storage_key,
                ),
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_minter_amount_storage_key,
                    correlation_response_id=correlation_response_id,
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

    async def _handle_deduction_request(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if not request.is_mint_request:
            raise ValueError("Should be a mint request")
        if not request.consider_amount_negative:
            raise ValueError("Should be a deduction request")

        self._logger.debug(f"Processing deduction request {request.id}")

        correlation_response_id = response_id
        is_total_amount_zero = not request.sender_balance_storage_key or all(
            b == 0 for b in request.sender_balance_storage_key
        )
        is_minter_balance_zero = not request.receiver_balance_storage_key or all(
            b == 0 for b in request.receiver_balance_storage_key
        )
        if is_total_amount_zero or is_minter_balance_zero:
            self._logger.debug(
                LogMessage(
                    message="Invalid deduction request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_total_amount_zero": is_total_amount_zero,
                        "is_minter_balance_zero": is_minter_balance_zero,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

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
        deduction_amount = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
            )
        )
        if (
            not isinstance(current_total_amount, CipherText)
            or not isinstance(current_minter_amount, CipherText)
            or not isinstance(deduction_amount, CipherText)
        ):
            self._logger.error(
                LogMessage(
                    message="Invalid operand types for deduction request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_current_total_amount_corrupted": not isinstance(
                            current_total_amount, CipherText
                        ),
                        "is_current_minter_amount_corrupted": not isinstance(
                            current_minter_amount, CipherText
                        ),
                        "is_deduction_amount_corrupted": not isinstance(
                            deduction_amount, CipherText
                        ),
                        "current_total_amount": (
                            b64encode(
                                serialize_single(
                                    self._client_node.cryptosystem, current_total_amount
                                )
                            ).decode("ascii")
                            if isinstance(current_total_amount, CipherText)
                            else b64encode(
                                serialize_bitwise(
                                    self._client_node.cryptosystem, current_total_amount
                                )
                            ).decode("ascii")
                        ),
                        "current_minter_amount": (
                            b64encode(
                                serialize_single(
                                    self._client_node.cryptosystem,
                                    current_minter_amount,
                                )
                            ).decode("ascii")
                            if isinstance(current_minter_amount, CipherText)
                            else b64encode(
                                serialize_bitwise(
                                    self._client_node.cryptosystem,
                                    current_minter_amount,
                                )
                            ).decode("ascii")
                        ),
                        "deduction_amount": (
                            b64encode(
                                serialize_single(
                                    self._client_node.cryptosystem, deduction_amount
                                )
                            ).decode("ascii")
                            if isinstance(deduction_amount, CipherText)
                            else b64encode(
                                serialize_bitwise(
                                    self._client_node.cryptosystem, deduction_amount
                                )
                            ).decode("ascii")
                        ),
                        "deduction_amount": deduction_amount,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        # Do a normal transfer with total amount as receiver and minter amount as sender
        # if it passes subtract double the amount from the total amount
        sucess, new_balances = native_transfer_func(
            self._client_node,
            current_minter_amount,
            current_total_amount,
            deduction_amount,
        )

        if not sucess:
            self._logger.debug(
                f"Deduction request failed {request.id} because of insufficient balance"
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        new_minter_amount = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            new_balances[0],
        )
        ekn = self._client_node.network_encryption_key
        new_total_amount = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            self._client_node.cryptosystem.add_ciphertexts(
                ekn,
                new_balances[1],
                self._client_node.cryptosystem.negate_ciphertext(
                    ekn,
                    self._client_node.cryptosystem.scal_ciphertext(
                        ekn,
                        self._client_node.cryptosystem.make_plaintext(float(2)),
                        current_total_amount,
                    ),
                ),
            ),
        )

        new_total_amount_storage_key = self._get_new_storage_key()
        new_minter_amount_storage_key = self._get_new_storage_key()
        self._save_operand(
            new_total_amount_storage_key,
            new_total_amount,
            self._get_acl_for_storage_key(
                request.sender_balance_storage_key,
            ),
        )
        self._save_operand(
            new_minter_amount_storage_key,
            new_minter_amount,
            self._get_acl_for_storage_key(
                request.receiver_balance_storage_key,
            ),
        )
        with self._eagerly_evaluated_confidential_coin_request_responses_lock:
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

    async def _process_request_tee(
        self, accepted_response: Response, request: Request
    ) -> Response:
        if request.operation == Operation.RETRIEVE:
            return await self._handle_retrieve(accepted_response, request)
        if request.operation == Operation.STORE:
            return await self._handle_store_request(accepted_response, request)
        if request.operation == Operation.RETRIEVE_REENCRYPT:
            return await self._handle_retrieve_reencrypt(accepted_response, request)

        if accepted_response.result is None:
            self._logger.error(
                LogMessage(
                    message="Invalid accepted response, result is None",
                    structured_log_message_data={
                        "request_id": request.id,
                        "accepted_response": accepted_response.model_dump_json(),
                    },
                )
            )
            raise ValueError("Invalid accepted response, result is None")

        op1 = self._get_cofhe_operand(request.op1)
        op2 = self._get_cofhe_operand(request.op2)

        dec_op1 = None
        dec_op2 = None

        if request.op1.encryption_scheme == OperandEncryptionScheme.CLHSM2k:
            if isinstance(op1, CipherText):
                dec_op1 = self._decrypt_single(self._client_node, op1)
            elif isinstance(op1, list):
                dec_op1 = self._decrypt_bitwise(self._client_node, op1)
            else:
                self._logger.error(
                    LogMessage(
                        message="Invalid operand type for TEE request",
                        structured_log_message_data={
                            "request_id": request.id,
                            "op1": op1,
                        },
                    )
                )
                raise ValueError("Invalid operand type for TEE request")
        else:
            raise ValueError(
                "Invalid encryption scheme for TEE request, should be CLHSM2k"
            )

        if request.op2.encryption_scheme == OperandEncryptionScheme.CLHSM2k:
            if isinstance(op2, CipherText):
                dec_op2 = self._decrypt_single(self._client_node, op2)
            elif isinstance(op2, list):
                dec_op2 = self._decrypt_bitwise(self._client_node, op2)
            else:
                self._logger.error(
                    LogMessage(
                        message="Invalid operand type for TEE request",
                        structured_log_message_data={
                            "request_id": request.id,
                            "op2": op2,
                        },
                    )
                )
                raise ValueError("Invalid operand type for TEE request")
        else:
            raise ValueError(
                "Invalid encryption scheme for TEE request, should be CLHSM2k"
            )

        if dec_op1 is None or dec_op2 is None:
            self._logger.error(
                LogMessage(
                    message="Invalid decrypted operands for TEE request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "dec_op1": dec_op1,
                        "dec_op2": dec_op2,
                    },
                )
            )
            raise ValueError("Invalid decrypted operands for TEE request")

        result = None

        if request.operation == Operation.ADD:
            result = dec_op1 + dec_op2
        elif request.operation == Operation.SUB:
            result = dec_op1 - dec_op2
        elif request.operation == Operation.EQ:
            result = 1 if dec_op1 == dec_op2 else 0
        elif request.operation == Operation.LT:
            result = 1 if dec_op1 < dec_op2 else 0
        elif request.operation == Operation.GT:
            result = 1 if dec_op1 > dec_op2 else 0
        elif request.operation == Operation.GTEQ:
            result = 1 if dec_op1 >= dec_op2 else 0
        elif request.operation == Operation.LTEQ:
            result = 1 if dec_op1 <= dec_op2 else 0
        elif request.operation == Operation.NAND:
            # result = ~(dec_op1 & dec_op2)
            raise NotImplementedError("TEE requests for NAND operation not implemented")
        else:
            self._logger.error(
                LogMessage(
                    message="Invalid operation for TEE request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "operation": request.operation,
                    },
                )
            )
            raise ValueError("Invalid operation for TEE request")
        if result is None:
            self._logger.error(
                LogMessage(
                    message="Invalid result for TEE request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "dec_op1": dec_op1,
                        "dec_op2": dec_op2,
                    },
                )
            )
            raise ValueError("Invalid result for TEE request")

        encrypted_result: CipherText | List[CipherText] | None = None
        if isinstance(op1, CipherText):
            encrypted_result = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                result,
            )
        elif isinstance(op1, list):
            encrypted_result = encrypt_bitwise(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                result,
            )

        if encrypted_result is None:
            self._logger.error(
                LogMessage(
                    message="Invalid encrypted result for TEE request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "result": result,
                    },
                )
            )
            raise ValueError("Invalid encrypted result for TEE request")

        result_operand = self._make_operand(
            self._get_result_data_type(
                request.operation, request.op1.data_type, request.op2.data_type
            ),
            OperandLocation.STORAGE_KEY,
            self._get_result_encryption_scheme(
                request.operation,
                request.op1.encryption_scheme,
                request.op2.encryption_scheme,
            ),
            encrypted_result,
        )

        new_storage_key = self._get_storage_key(accepted_response.result)
        self._save_operand(
            new_storage_key,
            result_operand,
            self._get_acl_for_storage_key(request.op1.data),
        )
        self._logger.debug(
            LogMessage(
                message="TEE request processed successfully",
                structured_log_message_data={
                    "request_id": request.id,
                    "result_storage_key": new_storage_key,
                    "result": result_operand.data,
                },
            )
        )

        result_operand_p = self._make_operand(
            result_operand.data_type,
            OperandLocation.STORAGE_KEY,
            result_operand.encryption_scheme,
            new_storage_key,
        )

        return Response(
            id=uuid.uuid4().hex,
            request_id=request.id,
            status=ResponseStatus.SUCCESS,
            result=result_operand_p,
            correlation_response_id=accepted_response.id,
        )

    async def _process_confidential_coin_request_tee(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if request.is_mint_request:
            return await self._process_mint_request_tee(request, response_id)
        return await self._process_transfer_request_tee(request, response_id)

    async def _process_transfer_request_tee(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if request.is_mint_request:
            raise ValueError("Should be a transfer request")

        self._logger.debug(f"Processing transfer request in tee {request.id}")

        if request.consider_amount_negative:
            self._logger.debug(
                LogMessage(
                    message="Invalid transfer request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "consider_amount_negative": request.consider_amount_negative,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=response_id,
                )
            return ConfidentialCoinResponse(
                id=response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        sender_balance_enc = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.STORAGE_KEY,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=request.sender_balance_storage_key,
            )
        )
        receiver_balance_enc = None
        receiver_not_registered = (not request.receiver_balance_storage_key) or all(
            b == 0 for b in request.receiver_balance_storage_key
        )
        if not receiver_not_registered:
            receiver_balance_enc = self._get_cofhe_operand(
                Operand(
                    data_type=DataType.SINGLE,
                    location=OperandLocation.STORAGE_KEY,
                    encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                    data=request.receiver_balance_storage_key,
                )
            )
        amount_enc = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
            )
        )
        if (
            not isinstance(sender_balance_enc, CipherText)
            or (
                not isinstance(receiver_balance_enc, CipherText)
                and not receiver_not_registered
            )
            or not isinstance(amount_enc, CipherText)
        ):
            self._logger.error(
                LogMessage(
                    message="Invalid operand types for transfer request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_sender_balance_corrupted": (
                            not isinstance(sender_balance_enc, CipherText)
                        ),
                        "is_receiver_balance_corrupted": (
                            not isinstance(receiver_balance_enc, CipherText)
                            and not receiver_not_registered
                        ),
                        "is_amount_corrupted": (not isinstance(amount_enc, CipherText)),
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=response_id,
                )
            return ConfidentialCoinResponse(
                id=response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        start_time = datetime.now()
        sender_balance = self._decrypt_single(self._client_node, sender_balance_enc)
        receiver_balance = (
            self._decrypt_single(self._client_node, receiver_balance_enc)
            if isinstance(receiver_balance_enc, CipherText)
            else 0
        )
        amount = self._decrypt_single(self._client_node, amount_enc)

        success, sender_balance_storage_key, receiver_balance_storage_key = (
            None,
            None,
            None,
        )

        if sender_balance < amount:
            success = False
            sender_balance_storage_key = request.sender_balance_storage_key
            receiver_balance_storage_key = request.receiver_balance_storage_key
            end_time = datetime.now()
        else:
            success = True
            new_sender_balance_pt = sender_balance - amount
            new_receiver_balance_pt = receiver_balance + amount
            new_sender_balance = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                new_sender_balance_pt,
            )
            new_receiver_balance = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                new_receiver_balance_pt,
            )
            end_time = datetime.now()
            sender_balance_storage_key = self._get_new_storage_key()
            receiver_balance_storage_key = self._get_new_storage_key()
            self._save_operand(
                sender_balance_storage_key,
                self._make_operand(
                    DataType.SINGLE,
                    OperandLocation.VALUE,
                    OperandEncryptionScheme.CLHSM2k,
                    new_sender_balance,
                ),
                self._get_acl_for_storage_key(request.sender_balance_storage_key),
            )
            self._save_operand(
                receiver_balance_storage_key,
                self._make_operand(
                    DataType.SINGLE,
                    OperandLocation.VALUE,
                    OperandEncryptionScheme.CLHSM2k,
                    new_receiver_balance,
                ),
                (
                    request.receiver_balance_storage_key_acl
                    if receiver_not_registered
                    else self._get_acl_for_storage_key(
                        request.receiver_balance_storage_key
                    )
                ),
            )
        self._logger.debug(
            LogMessage(
                message="Transfer request processed in TEE",
                structured_log_message_data={
                    "request_id": request.id,
                    "success": success,
                    "sender_balance_storage_key": sender_balance_storage_key,
                    "receiver_balance_storage_key": receiver_balance_storage_key,
                    "processing_time_seconds": (end_time - start_time).microseconds,
                },
            )
        )
        correlation_response_id = response_id
        with self._eagerly_evaluated_confidential_coin_request_responses_lock:
            self._eagerly_evaluated_confidential_coin_request_responses[request.id] = (
                ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=success,
                    sender_balance_storage_key=sender_balance_storage_key,
                    receiver_balance_storage_key=receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            )
        return ConfidentialCoinResponse(
            id=correlation_response_id,
            request_id=request.id,
            status=ResponseStatus.ACCEPTED,
            success=success,
            sender_balance_storage_key=sender_balance_storage_key,
            receiver_balance_storage_key=receiver_balance_storage_key,
        )

    async def _process_mint_request_tee(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if not request.is_mint_request:
            raise ValueError("Should be a mint request")

        self._logger.debug(f"Processing mint request in tee {request.id}")

        if request.consider_amount_negative:
            return await self._handle_deduction_request_tee(request, response_id)

        correlation_response_id = response_id
        is_total_amount_zero = not request.sender_balance_storage_key or all(
            b == 0 for b in request.sender_balance_storage_key
        )
        is_minter_balance_zero = not request.receiver_balance_storage_key or all(
            b == 0 for b in request.receiver_balance_storage_key
        )

        if is_total_amount_zero and (not is_minter_balance_zero):
            self._logger.debug(
                LogMessage(
                    message="Invalid mint request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_total_amount_zero": is_total_amount_zero,
                        "is_minter_balance_zero": is_minter_balance_zero,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_OPERATION,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        if is_total_amount_zero and is_minter_balance_zero:
            new_total_amount = Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_receiver_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                request.sender_balance_storage_key_acl,
            )
            self._save_operand(
                new_receiver_amount_storage_key,
                new_total_amount,
                request.receiver_balance_storage_key_acl,
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_receiver_amount_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=True,
                sender_balance_storage_key=new_total_amount_storage_key,
                receiver_balance_storage_key=new_total_amount_storage_key,
            )

        if (not is_total_amount_zero) and (is_minter_balance_zero):
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
                    data=(
                        request.amount
                        if isinstance(request.amount, bytes)
                        else self._encrypt_and_serialize(
                            request.amount,
                        )
                    ),
                )
            )
            if not isinstance(current_total_amount, CipherText) or not isinstance(
                mint_amount, CipherText
            ):
                self._logger.error(
                    LogMessage(
                        message="Invalid operand types for mint request",
                        structured_log_message_data={
                            "request_id": request.id,
                            "is_current_total_amount_corrupted": not isinstance(
                                current_total_amount, CipherText
                            ),
                            "is_mint_amount_corrupted": not isinstance(
                                mint_amount, CipherText
                            ),
                        },
                    )
                )
                with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                    self._eagerly_evaluated_confidential_coin_request_responses[
                        request.id
                    ] = ConfidentialCoinResponse(
                        id=uuid.uuid4().hex,
                        request_id=request.id,
                        status=ResponseStatus.INVALID_DATA_TYPE,
                        success=False,
                        sender_balance_storage_key=request.sender_balance_storage_key,
                        receiver_balance_storage_key=request.receiver_balance_storage_key,
                        correlation_response_id=correlation_response_id,
                    )
                return ConfidentialCoinResponse(
                    id=correlation_response_id,
                    request_id=request.id,
                    status=ResponseStatus.ACCEPTED,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                )
            start_time = datetime.now()
            current_total_amount_dec = self._decrypt_single(
                self._client_node, current_total_amount
            )
            mint_amount_dec = self._decrypt_single(self._client_node, mint_amount)
            new_total_amount_enc = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                current_total_amount_dec + mint_amount_dec,
            )
            new_receiver_amount_enc = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                mint_amount_dec,
            )
            end_time = datetime.now()
            self._logger.debug(
                LogMessage(
                    message="Mint request decryption and encryption processed for case where minter balance is zero",
                    structured_log_message_data={
                        "request_id": request.id,
                        "processing_time": (end_time - start_time).microseconds,
                    },
                )
            )
            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                new_total_amount_enc,
            )
            new_receiver_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                new_receiver_amount_enc,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_receiver_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                self._get_acl_for_storage_key(
                    request.sender_balance_storage_key,
                ),
            )
            self._save_operand(
                new_receiver_amount_storage_key,
                new_receiver_amount,
                request.receiver_balance_storage_key_acl,
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_receiver_amount_storage_key,
                    correlation_response_id=correlation_response_id,
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
                    data=(
                        request.amount
                        if isinstance(request.amount, bytes)
                        else self._encrypt_and_serialize(
                            request.amount,
                        )
                    ),
                )
            )
            if (
                not isinstance(current_total_amount, CipherText)
                or not isinstance(current_minter_amount, CipherText)
                or not isinstance(mint_amount, CipherText)
            ):
                self._logger.error(
                    LogMessage(
                        message="Invalid operand types for mint request",
                        structured_log_message_data={
                            "request_id": request.id,
                            "is_current_total_amount_corrupted": not isinstance(
                                current_total_amount, CipherText
                            ),
                            "is_current_minter_amount_corrupted": not isinstance(
                                current_minter_amount, CipherText
                            ),
                            "is_mint_amount_corrupted": not isinstance(
                                mint_amount, CipherText
                            ),
                        },
                    )
                )
                with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                    self._eagerly_evaluated_confidential_coin_request_responses[
                        request.id
                    ] = ConfidentialCoinResponse(
                        id=uuid.uuid4().hex,
                        request_id=request.id,
                        status=ResponseStatus.INVALID_DATA_TYPE,
                        success=False,
                        sender_balance_storage_key=request.sender_balance_storage_key,
                        receiver_balance_storage_key=request.receiver_balance_storage_key,
                        correlation_response_id=correlation_response_id,
                    )
                return ConfidentialCoinResponse(
                    id=correlation_response_id,
                    request_id=request.id,
                    status=ResponseStatus.ACCEPTED,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                )
            start_time = datetime.now()
            current_total_amount_dec = self._decrypt_single(
                self._client_node, current_total_amount
            )
            current_minter_amount_dec = self._decrypt_single(
                self._client_node, current_minter_amount
            )
            mint_amount_dec = self._decrypt_single(self._client_node, mint_amount)
            new_total_amount_enc = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                current_total_amount_dec + mint_amount_dec,
            )
            new_minter_amount_enc = encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                current_minter_amount_dec + mint_amount_dec,
            )
            end_time = datetime.now()
            self._logger.debug(
                LogMessage(
                    message="Mint request decryption and encryption processed for case where both balances are non-zero",
                    structured_log_message_data={
                        "request_id": request.id,
                        "processing_time": (end_time - start_time).microseconds,
                    },
                )
            )
            new_total_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                new_total_amount_enc,
            )
            new_minter_amount = self._make_operand(
                DataType.SINGLE,
                OperandLocation.VALUE,
                OperandEncryptionScheme.CLHSM2k,
                new_minter_amount_enc,
            )
            new_total_amount_storage_key = self._get_new_storage_key()
            new_minter_amount_storage_key = self._get_new_storage_key()
            self._save_operand(
                new_total_amount_storage_key,
                new_total_amount,
                self._get_acl_for_storage_key(
                    request.sender_balance_storage_key,
                ),
            )
            self._save_operand(
                new_minter_amount_storage_key,
                new_minter_amount,
                self._get_acl_for_storage_key(
                    request.receiver_balance_storage_key,
                ),
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=True,
                    sender_balance_storage_key=new_total_amount_storage_key,
                    receiver_balance_storage_key=new_minter_amount_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=True,
                sender_balance_storage_key=new_total_amount_storage_key,
                receiver_balance_storage_key=new_minter_amount_storage_key,
            )

        raise ValueError("Invalid mint request, should not reach here. ")

    async def _handle_deduction_request_tee(
        self, request: ConfidentialCoinRequest, response_id: str
    ) -> ConfidentialCoinResponse:
        if request.is_mint_request:
            raise ValueError("Should be a deduction request")

        self._logger.debug(f"Processing deduction request in tee {request.id}")

        if not request.consider_amount_negative:
            self._logger.debug(
                LogMessage(
                    message="Invalid deduction request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "consider_amount_negative": request.consider_amount_negative,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_OPERATION,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=response_id,
                )
            return ConfidentialCoinResponse(
                id=response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        correlation_response_id = response_id
        is_total_amount_zero = not request.sender_balance_storage_key or all(
            b == 0 for b in request.sender_balance_storage_key
        )
        is_minter_balance_zero = not request.receiver_balance_storage_key or all(
            b == 0 for b in request.receiver_balance_storage_key
        )
        if is_total_amount_zero or is_minter_balance_zero:
            self._logger.debug(
                LogMessage(
                    message="Invalid deduction request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_total_amount_zero": is_total_amount_zero,
                        "is_minter_balance_zero": is_minter_balance_zero,
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.SUCCESS,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )
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
        deduction_amount = self._get_cofhe_operand(
            Operand(
                data_type=DataType.SINGLE,
                location=OperandLocation.VALUE,
                encryption_scheme=OperandEncryptionScheme.CLHSM2k,
                data=(
                    request.amount
                    if isinstance(request.amount, bytes)
                    else self._encrypt_and_serialize(
                        request.amount,
                    )
                ),
            )
        )

        if (
            not isinstance(current_total_amount, CipherText)
            or not isinstance(current_minter_amount, CipherText)
            or not isinstance(deduction_amount, CipherText)
        ):
            self._logger.error(
                LogMessage(
                    message="Invalid operand types for deduction request",
                    structured_log_message_data={
                        "request_id": request.id,
                        "is_current_total_amount_corrupted": not isinstance(
                            current_total_amount, CipherText
                        ),
                        "is_current_minter_amount_corrupted": not isinstance(
                            current_minter_amount, CipherText
                        ),
                        "is_deduction_amount_corrupted": not isinstance(
                            deduction_amount, CipherText
                        ),
                    },
                )
            )
            with self._eagerly_evaluated_confidential_coin_request_responses_lock:
                self._eagerly_evaluated_confidential_coin_request_responses[
                    request.id
                ] = ConfidentialCoinResponse(
                    id=uuid.uuid4().hex,
                    request_id=request.id,
                    status=ResponseStatus.INVALID_DATA_TYPE,
                    success=False,
                    sender_balance_storage_key=request.sender_balance_storage_key,
                    receiver_balance_storage_key=request.receiver_balance_storage_key,
                    correlation_response_id=correlation_response_id,
                )
            return ConfidentialCoinResponse(
                id=correlation_response_id,
                request_id=request.id,
                status=ResponseStatus.ACCEPTED,
                success=False,
                sender_balance_storage_key=request.sender_balance_storage_key,
                receiver_balance_storage_key=request.receiver_balance_storage_key,
            )

        current_total_amount_dec = self._decrypt_single(
            self._client_node, current_total_amount
        )
        current_minter_amount_dec = self._decrypt_single(
            self._client_node, current_minter_amount
        )
        deduction_amount_dec = self._decrypt_single(self._client_node, deduction_amount)
        new_total_amount = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                current_total_amount_dec - deduction_amount_dec,
            ),
        )
        new_minter_amount = self._make_operand(
            DataType.SINGLE,
            OperandLocation.VALUE,
            OperandEncryptionScheme.CLHSM2k,
            encrypt_single(
                self._client_node.cryptosystem,
                self._client_node.network_encryption_key,
                current_minter_amount_dec - deduction_amount_dec,
            ),
        )
        new_total_amount_storage_key = self._get_new_storage_key()
        new_minter_amount_storage_key = self._get_new_storage_key()
        self._save_operand(
            new_total_amount_storage_key,
            new_total_amount,
            self._get_acl_for_storage_key(
                request.sender_balance_storage_key,
            ),
        )
        self._save_operand(
            new_minter_amount_storage_key,
            new_minter_amount,
            self._get_acl_for_storage_key(
                request.receiver_balance_storage_key,
            ),
        )
        with self._eagerly_evaluated_confidential_coin_request_responses_lock:
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

    async def process_confidential_coin_request(
        self,
        accepted_response: ConfidentialCoinResponse,
        request: ConfidentialCoinRequest,
    ) -> ConfidentialCoinResponse:
        if accepted_response.status != ResponseStatus.ACCEPTED:
            raise ValueError("Invalid response status")

        with self._eagerly_evaluated_confidential_coin_request_responses_lock:
            if (
                request.id
                not in self._eagerly_evaluated_confidential_coin_request_responses
            ):
                self._logger.error(
                    LogMessage(
                        message="Invalid request id",
                        structured_log_message_data={
                            "request_id": request.id,
                            "accepted_response": accepted_response.model_dump_json(),
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
        if (
            request.verified_origin
            not in self._get_acl_for_storage_key(request.op1.data)
        ) and (
            not self._open_for_everyone(self._get_acl_for_storage_key(request.op1.data))
        ):
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.SUCCESS,
                result=None,
                correlation_response_id=accepted_response.id,
            )

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

        self._save_operand(
            self._get_storage_key(accepted_response.result),
            request.op1,
            [request.verified_origin],
        )
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
        perms: list[bytes] = [request.verified_origin]
        if (
            request.op1.location == OperandLocation.STORAGE_KEY
            and request.op2.location == OperandLocation.STORAGE_KEY
        ):
            perms = self._get_acl_and(
                self._get_acl_for_storage_key(request.op1.data),
                self._get_acl_for_storage_key(request.op2.data),
            )
        if request.op1.location == OperandLocation.STORAGE_KEY:
            perms = self._get_acl_for_storage_key(request.op1.data)
        if request.op2.location == OperandLocation.STORAGE_KEY:
            perms = self._get_acl_for_storage_key(request.op2.data)

        self._save_operand(new_storage_key, result_p, perms)
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

        return res.data

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

    def _save_operand(self, key: bytes, op: Operand, acl: List[bytes]) -> None:
        # if acl is empty save [b""]
        # the b"" represents everyone has access to the operand
        if not acl:
            acl = [b""]
        key_str = key.hex()
        self._logger.debug(
            LogMessage(
                message="Saving operand",
                structured_log_message_data={
                    "key": key_str,
                    "operand": json.dumps(self._make_operand_dict(op, acl)),
                },
            )
        )
        self._storage.put(key_str, self._serialize_operand(op, acl))

    def _get_acl_for_storage_key(self, storage_key: bytes) -> List[bytes]:
        storage_key_str = self._convert_bytes_to_storage_key(storage_key).hex()
        if self._storage.check(storage_key_str):
            data = json.loads(self._storage.get(storage_key_str))
            self._verify_operand_data(data)
            return [b64decode(a) for a in data["acl"]]
        raise KeyError(f"Storage key {storage_key_str} not found")

    def _open_for_everyone(self, acl: List[bytes]) -> bool:
        if b"" in acl:
            return True
        return False

    def _get_acl_and(self, acl1: List[bytes], acl2: List[bytes]) -> List[bytes]:
        return list(set(acl1) & set(acl2))

    def _serialize_operand(self, op: Operand, acl: List[bytes]) -> str:
        # The format is json, with operand properties as keys and values as values
        return json.dumps(self._make_operand_dict(op, acl))

    def _deserialize_operand(self, data: str) -> Operand:
        return self._make_operand_from_dict(json.loads(data))

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

    def _make_operand_dict(self, op: Operand, acl: List[bytes]) -> dict:
        return {
            "data_type": op.data_type.value,
            "location": op.location.value,
            "encryption_scheme": op.encryption_scheme.value,
            "data": b64encode(op.data).decode("ascii"),
            "acl": [b64encode(a).decode("ascii") for a in acl],
        }

    def _make_operand_from_dict(self, data: dict) -> Operand:
        self._verify_operand_data(data)
        return Operand(
            data_type=DataType(data["data_type"]),
            location=OperandLocation(data["location"]),
            encryption_scheme=OperandEncryptionScheme(data["encryption_scheme"]),
            data=b64decode(data["data"]),
        )

    def _verify_operand_data(self, data: dict) -> None:
        try:
            self._verify_operand_data_inner(data)
        except Exception as e:
            self._logger.error(
                LogMessage(
                    message="Invalid operand data",
                    structured_log_message_data={
                        "error": e,
                        "data": json.dumps(data),
                    },
                )
            )
            raise e

    def _verify_operand_data_inner(self, data: dict) -> None:
        if "encryption_scheme" not in data:
            raise ValueError("Invalid operand encryption scheme")
        if not isinstance(data["encryption_scheme"], str):
            raise ValueError("Invalid operand encryption scheme format")
        try:
            OperandEncryptionScheme(data["encryption_scheme"])
        except ValueError:
            raise ValueError("Invalid operand encryption scheme value")
        if "location" not in data:
            raise ValueError("Invalid operand location")
        if not isinstance(data["location"], str):
            raise ValueError("Invalid operand location format")
        try:
            OperandLocation(data["location"])
        except ValueError:
            raise ValueError("Invalid operand location value")
        if "data_type" not in data:
            raise ValueError("Invalid operand data type")
        if not isinstance(data["data_type"], str):
            raise ValueError("Invalid operand data type format")
        try:
            DataType(data["data_type"])
        except ValueError:
            raise ValueError("Invalid operand data type value")
        if "data" not in data:
            raise ValueError("Invalid operand data")
        if not isinstance(data["data"], str):
            raise ValueError("Invalid operand data format")
        if "acl" not in data:
            raise ValueError("Invalid operand ACL")
        if not isinstance(data["acl"], list):
            raise ValueError("Invalid operand ACL format")
        if not all(isinstance(a, str) for a in data["acl"]):
            raise ValueError("Invalid operand ACL format")

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
    
    def _decrypt_single(
        self, client_node: CPUCryptoSystemClientNode, ciphertext: CipherText
    ) -> int:
        # once a particular tee reencryption key is implemented, use reencryption
        return decrypt_single(client_node, ciphertext)
    
    def _decrypt_bitwise(
        self, client_node: CPUCryptoSystemClientNode, ciphertext: List[CipherText]
    ) -> int:
        # once a particular tee reencryption key is implemented, use reencryption
        return decrypt_bitwise(client_node, ciphertext)
    
    def _get_tee_reencryption_key(
        self
    )-> bytes:
        raise NotImplementedError(
            "TEE reencryption key retrieval is not implemented in this version of the service."
        )


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
                        "error": e,
                    },
                )
            )
            raise ValueError(
                f"Unable to connect to setup node at {config.setup_node_ip}:{config.setup_node_port} or"
                + f"client node at {config.client_node_ip}:{config.client_node_port}."
                + f"Please check the configuration and try again."
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
                            "error": e,
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
                        "error": e,
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
                                "request": request.request.model_dump_json(),
                            },
                        )
                    )
                else:
                    self._logger.debug(
                        LogMessage(
                            message="Processing confidential coin request",
                            structured_log_message_data={
                                "request_id": request.request.id,
                                "request": request.request.model_dump_json(),
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
                                "request": request.request.model_dump_json(),
                                "error": e,
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
                    "request": request.request.model_dump_json(),
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
                    "request": request.request.model_dump_json(),
                },
            )
        )
        return await self._client_node.process_confidential_coin_request_optimistic(
            request.request, request.response_id
        )

    def _wrap_async_function(self, func, *args, **kwargs) -> None:
        asyncio.run(func(*args, **kwargs))
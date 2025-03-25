from __future__ import annotations
import json
from typing import List

from typing_extensions import override
from abc import ABC, abstractmethod

from dataclasses import dataclass
from queue import Queue
from threading import Thread, Event
import asyncio
import uuid

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
)

from openvector_cofhe_coprocessor_backend.common.storage import Storage, FileStorage

from pycofhe.cpu_cryptosystem import CipherText
from pycofhe.network import make_cpucryptosystem_client_node, CPUCryptoSystemClientNode
from pycofhe.network import (
    decrypt_bit,
    homomorphic_nand,
    decrypt_bitwise,
    homomorphic_or,
    homomorphic_xor,
    homomorphic_not,
    homomorphic_add,
    homomorphic_sub,
    homomorphic_lt,
    homomorphic_eq,
    homomorphic_gt,
    serialize_bit,
    deserialize_bit,
    serialize_bitwise,
    deserialize_bitwise,
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
    def submit_request(self, request: Request) -> str:
        """Process the request"""
        pass

    @abstractmethod
    def response_available(self) -> bool:
        """Check the response"""
        pass

    @abstractmethod
    def get_response(self) -> Response:
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
    log_path: str
    log_level: str


class CPUCryptoSystemClientNodeWrapper:
    __slots__ = ("_client_node", "_storage")

    _client_node: CPUCryptoSystemClientNode
    _storage: Storage

    def __init__(
        self,
        client_node: CPUCryptoSystemClientNode,
        storage: Storage,
    ):
        self._client_node = client_node
        self._storage = storage

    async def get_optimistic_result(self, request: Request) -> Operand:
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
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.INVALID_OPERATION,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except KeyError as e:
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.UNKNOWN_DATA_STORAGE_KEY,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except ValueError as e:
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.INVALID_DATA_TYPE,
                result=None,
                correlation_response_id=accepted_response.id,
            )
        except Exception as e:
            return Response(
                id=uuid.uuid4().hex,
                request_id=request.id,
                status=ResponseStatus.FAILURE,
                result=None,
                correlation_response_id=accepted_response.id,
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

        storage_key = request.op1.data[:16]

        op = self._get_operand(storage_key)

        num = 0
        opc = self._get_cofhe_operand(op)
        if op.data_type == DataType.UINT32:
            if not isinstance(opc, list):
                raise ValueError("Invalid operand")
            num = decrypt_bitwise(self._client_node, opc)
        else:
            if not isinstance(opc, CipherText):
                raise ValueError("Invalid operand")
            num = decrypt_bit(self._client_node, opc)

        if request.op1.encryption_scheme == OperandEncryptionScheme.NONE:
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

        reenc_key = request.op1.data[16:]

        rsa_key = RSA.import_key(reenc_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        reenc_data = cipher.encrypt(num.to_bytes(32, byteorder="big"))
        reenc_op = Operand(
            data_type=request.op1.data_type,
            location=OperandLocation.VALUE,
            encryption_scheme=OperandEncryptionScheme.RSA,
            data=reenc_data,
        )
        return Response(
            id=uuid.uuid4().hex,
            request_id=request.id,
            status=ResponseStatus.SUCCESS,
            result=reenc_op,
            correlation_response_id=accepted_response.id,
        )

    async def _handle_store_request(
        self, accepted_response: Response, request: Request
    ) -> Response:
        if accepted_response.result is None:
            raise ValueError("Invalid response")
        if request.op1.location != OperandLocation.VALUE:
            raise ValueError("Invalid operand location")
        if request.op1.encryption_scheme != OperandEncryptionScheme.CLHSM2k:
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
            return homomorphic_or(self._client_node, op1, op2)
        if isinstance(op1, list) and isinstance(op2, list):
            return homomorphic_add(self._client_node, op1, op2)
        raise ValueError("Invalid operands")

    def _handle_sub(
        self, op1: CipherText | List[CipherText], op2: CipherText | List[CipherText]
    ) -> CipherText | List[CipherText]:
        if isinstance(op1, CipherText) and isinstance(op2, CipherText):
            return homomorphic_xor(self._client_node, op1, op2)
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

    def _get_cofhe_operand(self, operand: Operand) -> List[CipherText] | CipherText:
        # returns list of ciphertext if binary scheme is used and the data type is not single ie bit
        data = operand.data
        if operand.location == OperandLocation.STORAGE_KEY:
            ret_op = self._get_operand(operand.data)
            data = ret_op.data
        return self._parse_serialized_operand_data(data, operand.data_type)

    def _parse_serialized_operand_data(
        self, data_b: bytes, data_type: DataType
    ) -> List[CipherText] | CipherText:
        data = str(data_b, encoding="ascii")
        if data_type == DataType.BIT:
            return deserialize_bit(self._client_node.cryptosystem, data)
        if data_type == DataType.UINT32:
            return deserialize_bitwise(self._client_node.cryptosystem, data)
        raise ValueError(f"Invalid data type {data_type}")

    def _serialize_cofhe_operand_data(self, data: List[CipherText] | CipherText) -> str:
        if isinstance(data, CipherText):
            return serialize_bit(self._client_node.cryptosystem, data)
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
        print(f"Saving operand with key {key_str}")
        self._storage.put(key_str, self._serialize_operand(op))

    def _serialize_operand(self, op: Operand) -> str:
        # The format is json, with operand properties as keys and values as values
        return json.dumps(self._make_operand_dict(op))

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
            ac_data = bytes(self._serialize_cofhe_operand_data(data), encoding="utf-8")
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
            "data": str(op.data, encoding="utf-8"),
        }

    def _make_operand_from_dict(self, data: dict) -> Operand:
        if "data" not in data:
            data["data"] = ""
        if "encryption_scheme" not in data:
            data["encryption_scheme"] = OperandEncryptionScheme.NONE.value
        if "location" not in data:
            data["location"] = OperandLocation.VALUE.value
        if "data_type" not in data:
            data["data_type"] = DataType.UINT32.value
        return Operand(
            data_type=DataType(data["data_type"]),
            location=OperandLocation(data["location"]),
            encryption_scheme=OperandEncryptionScheme(data["encryption_scheme"]),
            data=bytes(data["data"], encoding="utf-8"),
        )

    def _get_optimistic_storage_key(self, request: Request) -> bytes:
        return self._get_new_storage_key()

    def _get_result_data_type(
        self, operation: Operation, data_type1: DataType, data_type2: DataType
    ) -> DataType:
        bit_ops = [
            Operation.LT,
            Operation.GT,
            Operation.EQ,
            Operation.LTEQ,
            Operation.GTEQ,
            Operation.NAND,
        ]
        uint32_ops = [Operation.ADD, Operation.SUB]
        non_det_ops = [Operation.RETRIEVE]
        same_type_ops = [Operation.STORE, Operation.RETRIEVE_REENCRYPT]
        if operation in same_type_ops:
            return data_type1
        if operation in non_det_ops:
            return data_type1
        if operation in bit_ops:
            return DataType.BIT
        if operation in uint32_ops:
            return DataType.UINT32
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


class CoreService(ICoreService):
    __slots__ = (
        "_client_node",
        "_config",
        "_request_queue",
        "_response_queue",
        "_exit_signal",
        "_worker_thread",
    )

    _client_node: CPUCryptoSystemClientNodeWrapper
    _config: CoreServiceConfig
    _request_queue: Queue[RequestWithResponseId]
    _response_queue: Queue[Response]
    _exit_signal: Event
    _worker_thread: Thread

    def __init__(self, config: CoreServiceConfig):
        self._client_node = CPUCryptoSystemClientNodeWrapper(
            make_cpucryptosystem_client_node(
                config.client_node_ip,
                config.client_node_port,
                config.setup_node_ip,
                config.setup_node_port,
                config.cert_path,
            ),
            FileStorage.create(config.storage_path, overwrite=config.storage_overwrite),
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
        self._worker_thread.start()

    @override
    def stop(self) -> None:
        self._exit_signal.set()
        self._worker_thread.join()
        print("Core service stopped")

    @override
    def submit_request(self, request: Request) -> str:
        response_id = uuid.uuid4().hex
        self._request_queue.put(
            RequestWithResponseId(request=request, response_id=response_id)
        )
        return response_id

    @override
    def response_available(self) -> bool:
        return not self._response_queue.empty()

    @override
    def get_response(self) -> Response:
        return self._response_queue.get()

    async def _worker(
        self,
        client_node: CPUCryptoSystemClientNodeWrapper,
        request_queue: Queue[RequestWithResponseId],
        response_queue: Queue[Response],
    ) -> None:
        while not self._exit_signal.is_set():
            if not request_queue.empty():
                # only process one request at a time
                request = request_queue.get()
                accepted_response = await self._accept_request(request)
                response_queue.put(accepted_response)
                if accepted_response.status != ResponseStatus.ACCEPTED:
                    continue
                response_queue.put(
                    await client_node.process_request(
                        accepted_response, request.request
                    )
                )
            else:
                await asyncio.sleep(0.1)

    async def _accept_request(self, request: RequestWithResponseId) -> Response:
        return Response(
            id=request.response_id,
            request_id=request.request.id,
            status=ResponseStatus.ACCEPTED,
            result=await self._client_node.get_optimistic_result(request.request),
        )

    def _wrap_async_function(self, func, *args, **kwargs) -> None:
        asyncio.run(func(*args, **kwargs))

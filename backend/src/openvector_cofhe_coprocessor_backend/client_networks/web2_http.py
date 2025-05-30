from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
from queue import Queue
from threading import Lock, Thread
from typing import Dict, List, Set
import uuid

from pydantic import BaseModel

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


from web3 import Web3
from eth_account.messages import encode_defunct

from openvector_cofhe_coprocessor_backend.common.logger import LogMessage, Logger
from openvector_cofhe_coprocessor_backend.client_networks.client_network_interface import (
    IClientNetwork,
)
from openvector_cofhe_coprocessor_backend.common.request_response import (
    Operation,
    Request,
    Response,
    ConfidentialCoinRequest,
    ConfidentialCoinResponse,
)


class HTTPStatus(StrEnum):
    """
    StrEnum for HTTP status codes.
    """

    OK = "OK"
    ERROR = "ERROR"
    UNAUTHORIZED = "UNAUTHORIZED"
    NONCE_NOT_FOUND = "NONCE_NOT_FOUND"


# this is not secure in http channel
class HTTPPreprocessRequest(BaseModel):
    """
    Request model for HTTP request preprocessing.
    This is used to generate a challenge/nonce for the request.
    For now not required for ConfidentialCoinRequest
    """

    # the respective HTTPRequestSubmissionRequest can contain
    # request with operation types allowed in this preprocess request
    # There can be any number of requests for a particular operation_type
    # in a HTTPRequestSubmissionRequest
    operation_types: Set[Operation]
    # verification proof is the signed message by the user
    # the message signed should be of format: json.dumps(operation_types,separators=(',', ':'))
    verification_proof: str


class HTTPPreprocessResponse(BaseModel):
    """
    Response model for HTTP request preprocessing.
    Contains a challenge/nonce that the user must sign with their private key.
    """

    status: HTTPStatus
    random_nonce: str


class HTTPRequestSubmissionRequest(BaseModel):
    """
    Request model for submitting HTTP requests.
    """

    random_nonce: str
    # in request object, the id must be empty string, ie ""
    # in request object of type Request, verified_origin must be empty bytes, ie b""
    # the bytes are encoded and decoded to/from base64 for json serialization
    requests: List[Request | ConfidentialCoinRequest]
    # verification proof is the signed message by the user
    # the message signed should be of format:
    # {
    #   "requests":json.dumps(request,separators=(',', ':'))
    #   "random_nonce": random_nonce,
    # }
    verification_proof: str


class HTTPRequestSubmissionResponse(BaseModel):
    """
    Response model for HTTP request submission.
    """

    status: HTTPStatus
    # the order is same as the requests in the HTTPRequestSubmissionRequest
    request_ids: List[str]


class HTTPResponseFetchRequest(BaseModel):
    """
    Request model for fetching HTTP responses.
    """

    request_id: List[str]


class HTTPResponseFetchResponse(BaseModel):
    """
    Response model for fetching HTTP responses.
    """

    status: HTTPStatus
    responses: Dict[str, List[Response] | List[ConfidentialCoinResponse]]


@dataclass(frozen=True, slots=True)
class Web2HTTPClientNetworkConfig:
    """
    Configuration for the Web2 HTTP client network.
    """

    port: int
    host: str
    ssl_key_path: str | None = None
    ssl_cert_path: str | None = None


class VerificationError(Exception):
    """
    Exception raised for verification errors in HTTP requests.
    This can be used to indicate that the request verification failed.
    """

    def __init__(self, message: str, extra: dict | None = None):
        super().__init__(message)
        self.extra = extra


class Web2HTTPClientNetwork(IClientNetwork):
    """
    A client network implementation for Web2 HTTP requests.
    This class uses FastAPI to handle HTTP requests and responses.
    Uvicorn server is run in a separate daemon thread.
    Shared data structures (_responses, _preprocess_requests) are protected by locks.
    """

    __slots__ = (
        "_app",
        "_config",
        "_preprocess_requests",
        "_requests",
        "_responses",
        "_logger",
        "_server_thread",
        "_responses_lock",
        "_preprocess_requests_lock",
    )
    _app: FastAPI
    _config: Web2HTTPClientNetworkConfig
    _preprocess_requests: Dict[str, HTTPPreprocessRequest]
    _requests: Queue[Request | ConfidentialCoinRequest]
    _responses: Dict[str, List[Response] | List[ConfidentialCoinResponse]]
    _logger: Logger
    _server_thread: Thread
    _responses_lock: Lock
    _preprocess_requests_lock: Lock

    def __init__(
        self,
        config: Web2HTTPClientNetworkConfig,
        logger: Logger,
        logger_config_path: str | None = None,
    ):
        """
        Initialize the Web2 HTTP client network with the given configuration.

        config: Configuration for the Web2 HTTP client network.
        logger: Logger instance for logging.
        """
        super().__init__("web2_http")
        self._logger = logger
        self._config = config
        self._preprocess_requests = {}
        self._requests = Queue()
        self._responses = {}
        self._app = FastAPI()
        self._app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        kwargs: dict = (
            {
                "ssl_keyfile": self._config.ssl_key_path,
                "ssl_certfile": self._config.ssl_cert_path,
            }
            if self._config.ssl_key_path and self._config.ssl_cert_path
            else {}
        )
        kwargs.update(
            {
                "host": self._config.host,
                "port": self._config.port,
            }
        )
        kwargs.update(
            {} if not logger_config_path else {"log_config": logger_config_path}
        )

        self._server_thread = Thread(
            target=uvicorn.run,
            args=(self._app,),
            kwargs=kwargs,
            daemon=True,
        )
        self._responses_lock = Lock()
        self._preprocess_requests_lock = Lock()
        self._setup_routes()

    def run(self) -> None:
        """
        Run the FastAPI application (Uvicorn server) in a separate daemon thread.
        """
        self._server_thread.start()
        self._logger.info(
            LogMessage(
                message=f"Uvicorn server starting on https://{self._config.host}:{self._config.port} in a separate thread."
            )
        )

    def stop(self) -> None:
        """
        Stop the FastAPI application.
        """
        self._logger.info(
            LogMessage(
                message="Web2HTTPClientNetwork stop called. Uvicorn server (it is running in a daemon thread) will exit with the main program."
            )
        )

    def request_available(self) -> bool:
        """
        Check if there are any requests available in the queue.
        """
        return not self._requests.empty()

    def get_request(self) -> Request | ConfidentialCoinRequest:
        """
        Get the next request from the queue.
        This method blocks until a request is available.
        """
        return self._requests.get()

    def put_response(self, response: Response | ConfidentialCoinResponse) -> None:
        """
        Put the response back into the responses dictionary.
        The response is indexed by its request ID.
        """
        with self._responses_lock:
            if self._responses.get(response.request_id, None) is not None:
                if isinstance(response, ConfidentialCoinResponse):
                    if isinstance(
                        self._responses[response.request_id][0],
                        ConfidentialCoinResponse,
                    ):
                        x = self._responses[response.request_id].append(response)  # type: ignore
                    else:
                        self._logger.error(
                            LogMessage(
                                message="Response type mismatch for request ID.",
                                structured_log_message_data={
                                    "request_id": response.request_id,
                                    "expected_type": ConfidentialCoinResponse,
                                    "actual_type": type(
                                        self._responses[response.request_id][0]
                                    ),
                                },
                            )
                        )
                else:
                    if isinstance(
                        self._responses[response.request_id][0],
                        Response,
                    ):
                        self._responses[response.request_id].append(response)  # type: ignore
                    else:
                        self._logger.error(
                            LogMessage(
                                message="Response type mismatch for request ID.",
                                structured_log_message_data={
                                    "request_id": response.request_id,
                                    "expected_type": ConfidentialCoinResponse,
                                    "actual_type": type(response),
                                },
                            )
                        )
            else:
                # for mypy
                if isinstance(response, ConfidentialCoinResponse):
                    self._responses[response.request_id] = [response]
                else:
                    self._responses[response.request_id] = [response]

    def _setup_routes(self):
        """
        Setup the HTTP routes for the FastAPI application.
        """

        @self._app.post("/request_preprocess", response_model=HTTPPreprocessResponse)
        async def handle_request_preprocess(
            request: HTTPPreprocessRequest,
        ) -> HTTPPreprocessResponse:
            op_types = list(request.operation_types)
            op_types.sort()  # Sort to ensure consistent order
            try:
                self._verify_signature(
                    verification_proof=request.verification_proof,
                    message=json.dumps(op_types, separators=(",", ":")),
                )
                random_nonce = self._generate_random_nonce()
                self._logger.debug(
                    LogMessage(
                        message="Processing preprocess request.",
                        structured_log_message_data={
                            "operation_types": op_types,
                            "verification_proof": request.verification_proof,
                            "random_nonce": random_nonce,
                        },
                    )
                )
                self._logger.debug(f"Generated random nonce: {random_nonce}")
                with self._preprocess_requests_lock:
                    self._preprocess_requests[random_nonce] = request
                return HTTPPreprocessResponse(
                    status=HTTPStatus.OK,
                    random_nonce=random_nonce,
                )
            except Exception as e:
                self._logger.error(
                    LogMessage(
                        message="Error processing preprocess request.",
                        structured_log_message_data={
                            "error": e,
                            "verification_proof": request.verification_proof,
                            "operation_types": op_types,
                        },
                    )
                )
                return HTTPPreprocessResponse(
                    status=HTTPStatus.ERROR,
                    random_nonce="",
                )

        @self._app.post("/request", response_model=HTTPRequestSubmissionResponse)
        async def handle_request(
            h_request: HTTPRequestSubmissionRequest,
        ) -> HTTPRequestSubmissionResponse:
            try:
                request_ids = []
                if h_request.random_nonce not in self._preprocess_requests:
                    self._logger.debug(
                        LogMessage(
                            message="Nonce not found for request submission.",
                            structured_log_message_data={
                                "random_nonce": h_request.random_nonce,
                                "verification_proof": h_request.verification_proof,
                                "requests": [
                                    req.model_dump_json() for req in h_request.requests
                                ],
                            },
                        )
                    )
                    return HTTPRequestSubmissionResponse(
                        status=HTTPStatus.NONCE_NOT_FOUND,
                        request_ids=[],
                    )
                verified_origin = self._generate_request_verified_origin(h_request)
                for request in h_request.requests:
                    actual_request: Request | ConfidentialCoinRequest | None = None
                    if isinstance(request, Request):
                        actual_request = Request(
                            id=self._generate_request_id(),
                            operation=request.operation,
                            op1=request.op1,
                            op2=request.op2,
                            verified_origin=verified_origin,
                        )
                    else:
                        actual_request = ConfidentialCoinRequest(
                            id=self._generate_request_id(),
                            is_mint_request=request.is_mint_request,
                            sender_balance_storage_key=request.sender_balance_storage_key,
                            receiver_balance_storage_key=request.receiver_balance_storage_key,
                            amount=request.amount,
                            consider_amount_negative=request.consider_amount_negative,
                            sender_balance_storage_key_acl=request.sender_balance_storage_key_acl,
                            receiver_balance_storage_key_acl=request.receiver_balance_storage_key_acl,
                        )
                    self._requests.put(actual_request)
                    request_ids.append(actual_request.id)
                return HTTPRequestSubmissionResponse(
                    status=HTTPStatus.OK,
                    request_ids=request_ids,
                )
            except VerificationError as ve:
                structured_log_message_data = {
                    "error": ve,
                    "random_nonce": h_request.random_nonce,
                    "verification_proof": h_request.verification_proof,
                    "requests": [req.model_dump_json() for req in h_request.requests],
                }
                if ve.extra:
                    structured_log_message_data.update(ve.extra)
                self._logger.debug(
                    LogMessage(
                        message="Verification failed for request submission.",
                        structured_log_message_data=structured_log_message_data,
                    )
                )
                return HTTPRequestSubmissionResponse(
                    status=HTTPStatus.UNAUTHORIZED,
                    request_ids=[],
                )
            except Exception as e:
                self._logger.error(
                    LogMessage(
                        message="Error processing request submission.",
                        structured_log_message_data={
                            "error": e,
                            "random_nonce": h_request.random_nonce,
                            "verification_proof": h_request.verification_proof,
                            "requests": [
                                req.model_dump_json() for req in h_request.requests
                            ],
                        },
                    )
                )
                return HTTPRequestSubmissionResponse(
                    status=HTTPStatus.ERROR,
                    request_ids=[],
                )

        @self._app.post("/response", response_model=HTTPResponseFetchResponse)
        async def handle_response(
            request: HTTPResponseFetchRequest,
        ) -> HTTPResponseFetchResponse:
            try:
                responses = {
                    req_id: self._responses.get(req_id, [])
                    for req_id in request.request_id
                }

                for req_id, resps in responses.items():
                    for resp in resps:
                        try:
                            self._responses[req_id].remove(resp)  # type: ignore
                        except ValueError:
                            self._logger.debug(
                                LogMessage(
                                    message="Response already removed.",
                                    structured_log_message_data={
                                        "request_id": req_id,
                                        "response_id": resp.id,
                                    },
                                )
                            )
                return HTTPResponseFetchResponse(
                    status=HTTPStatus.OK,
                    responses=responses,
                )
            except Exception as e:
                return HTTPResponseFetchResponse(
                    status=HTTPStatus.ERROR,
                    responses={},
                )

    def _generate_request_id(self) -> str:
        """
        Generate a unique request ID.
        """
        return uuid.uuid4().hex

    def _generate_random_nonce(self) -> str:
        """
        Generate a random nonce for the request.
        This is used to prevent replay attacks.
        """
        return uuid.uuid4().hex

    def _generate_request_verified_origin(
        self,
        request: HTTPRequestSubmissionRequest,
    ) -> bytes:
        """
        Generate a verified origin for the request.
        This will remove the preprocesing request from the dictionary
        """
        # pop first and then process to prevent TOCTOU issues
        preprocess_request = None
        with self._preprocess_requests_lock:
            preprocess_request = self._preprocess_requests.pop(
                request.random_nonce, None
            )
        if preprocess_request is None:
            raise VerificationError(
                "Invalid random nonce, no preprocess request found."
            )

        if not all(
            req.operation in preprocess_request.operation_types
            for req in request.requests
            if isinstance(req, Request)
        ):
            raise VerificationError(
                "Invalid operation types in request.",
                extra={
                    "allowed_operations": list(preprocess_request.operation_types),
                    "request_operations": [
                        req.operation
                        for req in request.requests
                        if isinstance(req, Request)
                    ],
                },
            )

        if any(req.id != "" for req in request.requests):
            raise VerificationError(
                "Invalid request ID, all requests must have empty ID.",
                extra={
                    "request_ids": [req.id for req in request.requests],
                },
            )

        if any(
            req.verified_origin != b""
            for req in request.requests
            if isinstance(req, Request)
        ):
            raise VerificationError(
                "Invalid verified origin, all requests must have empty verified origin.",
                extra={
                    "request_verified_origins": [
                        req.verified_origin
                        for req in request.requests
                        if isinstance(req, Request)
                    ],
                },
            )

        user_acc = self._verify_signature(
            verification_proof=preprocess_request.verification_proof,
            message=json.dumps(
                sorted(list(preprocess_request.operation_types)), separators=(",", ":")
            ),
        )
        self._verify_signature(
            verification_proof=request.verification_proof,
            message=json.dumps(
                {
                    "requests": [req.model_dump_json() for req in request.requests],
                    "random_nonce": request.random_nonce,
                },
                separators=(",", ":"),
            ),
            user_account_address=user_acc,
        )
        return user_acc

    def _verify_signature(
        self,
        verification_proof: str,
        message: str,
        user_account_address: bytes | None = None,
    ) -> bytes:
        """
        Verify the signature of the verification proof.
        """

        def convert_address_to_bytes(address: str) -> bytes:
            if address.startswith("0x"):
                address = address[2:]
            return bytes.fromhex(address.zfill(40))

        try:
            ver_acc = Web3().eth.account.recover_message(
                encode_defunct(text=message),
                signature=verification_proof,
            )
            ver_acc = convert_address_to_bytes(ver_acc)
            if user_account_address is not None:
                if ver_acc != user_account_address:
                    raise VerificationError(
                        "Verification proof does not match the user account address.",
                        extra={
                            "verification_proof": verification_proof,
                            "user_account_address": user_account_address.hex(),
                            "verified_account": ver_acc.hex(),
                        },
                    )
            return ver_acc
        except Exception as e:
            if isinstance(e, VerificationError):
                raise e
            raise VerificationError(
                "Signature verification failed.",
                extra={
                    "verification_proof": verification_proof,
                    "message": message,
                    "error": e,
                },
            )

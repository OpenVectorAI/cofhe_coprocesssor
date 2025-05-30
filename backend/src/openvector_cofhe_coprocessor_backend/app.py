from __future__ import annotations

from typing import Dict

import signal
import asyncio

from openvector_cofhe_coprocessor_backend.cli import CliArgs
from openvector_cofhe_coprocessor_backend.common.utils.json_utils import read_json_config
from openvector_cofhe_coprocessor_backend.common.logger import Logger, StandardLogger
from openvector_cofhe_coprocessor_backend.client_networks.client_network_interface import IClientNetwork
from openvector_cofhe_coprocessor_backend.core.core_service import (
    CoreServiceConfig,
    CoreService,
)
from openvector_cofhe_coprocessor_backend.client_networks.ethereum import (
    EthereumClientConfig,
    EthereumClientNetwork,
)
from openvector_cofhe_coprocessor_backend.client_networks.web2_http import (
    Web2HTTPClientNetwork,
    Web2HTTPClientNetworkConfig,
)
from openvector_cofhe_coprocessor_backend.common.request_response import ResponseStatus


config_schema = {
    "type": "object",
    "properties": {
        "client_networks": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["ethereum","web2_http"],
            },
        },
        "core_service": {
            "type": "object",
            "properties": {
                "client_node_ip": {"type": "string"},
                "client_node_port": {"type": "string"},
                "setup_node_ip": {"type": "string"},
                "setup_node_port": {"type": "string"},
                "cert_path": {"type": "string"},
                "storage_path": {"type": "string"},
                "storage_overwrite": {"type": "boolean"},
            },
            "required": [
                "client_node_ip",
                "client_node_port",
                "setup_node_ip",
                "setup_node_port",
                "cert_path",
                "storage_path",
                "storage_overwrite"
            ],
        },
        "logger": {
            "type": "object",
            "properties": {
                "config_path": {"type": "string"},
            },
            "required": ["config_path"],
        },
        "ethereum": {
            "type": "object",
            "properties": {
                "provider": {"type": "string"},
                "contract_address": {"type": "string"},
                "contract_abi_file_path": {"type": "string"},
                "owner_account_address": {"type": "string"},
                "owner_account_private_key": {"type": "string"},
            },
            "required": [
                "provider",
                "contract_address",
                "contract_abi_file_path",
                "owner_account_address",
                "owner_account_private_key",
            ],
        },
        "web2_http": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "ssl_key_path": {"type": "string"},
                "ssl_cert_path": {"type": "string"},
            },
            "required": [
                "host",
                "port",
            ],
        },

    },
    "required": [
        "client_networks",
        "core_service",
        "logger",
    ],
}


class App:
    __slots__ = (
        "_config",
        "_core_service",
        "_client_networks",
        "_cli_args",
        "_response_id_to_client_network_id",
        "_logger",
    )

    _config: dict
    _core_service: CoreService
    _client_networks: Dict[str, IClientNetwork]
    _cli_args: CliArgs
    _response_id_to_client_network_id: Dict[str, str]
    _logger: Logger

    def __init__(self, cli_args: CliArgs):
        self._cli_args = cli_args
        self._config = read_json_config(cli_args.config_file_path, config_schema)
        self._response_id_to_client_network_id = {}
        self._logger = StandardLogger(
            self._config["logger"]["config_path"],
        )
        self.__init()

    async def run(self):
        self._start_services()
        self._logger.info("App started")
        while True:
            self._handle_new_requests()
            self._handle_new_responses()
            await asyncio.sleep(0.1)

    def __init(self):
        self._logger.info("Initializing app")
        self._init_core_service()
        self._init_client_networks()
        self._register_signal_handlers()

    def _init_core_service(self):
        self._logger.info("Initializing core service")
        self._core_service = CoreService(
            CoreServiceConfig(
                client_node_ip=self._config["core_service"]["client_node_ip"],
                client_node_port=self._config["core_service"]["client_node_port"],
                setup_node_ip=self._config["core_service"]["setup_node_ip"],
                setup_node_port=self._config["core_service"]["setup_node_port"],
                cert_path=self._config["core_service"]["cert_path"],
                storage_path=self._config["core_service"]["storage_path"],
                storage_overwrite=self._config["core_service"]["storage_overwrite"]
            ),
            self._logger,
        )
        self._logger.info("Core service initialized")

    def _init_client_networks(self):
        self._logger.info("Initializing client networks")
        self._client_networks = {}
        for client_network in self._config["client_networks"]:
            if client_network == "ethereum":
                self._init_ethereum_client_network()
                self._logger.info("Ethereum client network initialized")
            elif client_network == "web2_http":
                self._init_web2_http_client_network()
                self._logger.info("Web2 HTTP client network initialized")
            else:
                raise ValueError(f"Unknown client network: {client_network}")
        if not self._client_networks:
            self._logger.error("No client network configured")
            raise ValueError("No client network configured")
        self._logger.info("Client networks initialized")

    def _init_ethereum_client_network(self):
        if "ethereum" not in self._config:
            self._logger.error("Ethereum client network is not configured")
            raise ValueError("Ethereum client network is not configured")

        ethereum_config = self._config["ethereum"]
        self._client_networks["ethereum"] = EthereumClientNetwork(
            EthereumClientConfig(
                provider=ethereum_config["provider"],
                contract_address=ethereum_config["contract_address"],
                contract_abi_file_path=ethereum_config["contract_abi_file_path"],
                owner_account_address=ethereum_config["owner_account_address"],
                owner_account_private_key=ethereum_config["owner_account_private_key"],
            ),
            self._logger
        )

    def _init_web2_http_client_network(self):
        if "web2_http" not in self._config:
            self._logger.error("Web2 HTTP client network is not configured")
            raise ValueError("Web2 HTTP client network is not configured")

        web2_http_config = self._config["web2_http"]
        self._client_networks["web2_http"] = Web2HTTPClientNetwork(
            Web2HTTPClientNetworkConfig(
                host=web2_http_config["host"],
                port=web2_http_config["port"],
                ssl_key_path=web2_http_config.get("ssl_key_path",None),
                ssl_cert_path=web2_http_config.get("ssl_cert_path",None),
            ),
            self._logger,
            self._config["logger"]["config_path"],
        )

    def _register_signal_handlers(self):
        signal.signal(signal.SIGINT, self._handle_sigint)
        signal.signal(signal.SIGTERM, self._handle_sigterm)

    def _handle_sigint(self, signum, frame):
        self._logger.info("Received SIGINT")
        self._stop_services()
        exit(0)

    def _handle_sigterm(self, signum, frame):
        self._logger.info("Received SIGTERM")
        self._stop_services()
        exit(0)

    def _stop_services(self):
        self._logger.info("Stopping services")
        self._core_service.stop()
        for client_network in self._client_networks.values():
            client_network.stop()
        self._logger.info("Services stopped")

    def _start_services(self):
        self._logger.info("Starting services")
        self._core_service.run()
        for client_network in self._client_networks.values():
            client_network.run()
        self._logger.info("Services started")

    def _handle_new_requests(self):
        for client_network in self._client_networks.values():
            if client_network.request_available():
                request = client_network.get_request()
                self._response_id_to_client_network_id[
                    self._core_service.submit_request(request)
                ] = client_network.id

    def _handle_new_responses(self):
        while self._core_service.response_available():
            response = self._core_service.get_response()

            client_network_id = self._response_id_to_client_network_id.get(response.id)
            correlated_id_used = False
            if client_network_id is None:
                client_network_id = self._response_id_to_client_network_id.get(
                    response.correlation_response_id
                )
                correlated_id_used = True
            if client_network_id is None:
                self._logger.error(
                    f"Response with id {response.id} or correlation response id {response.correlation_response_id} "
                    f"does not match any client network"
                )
                continue

            if response.status != ResponseStatus.ACCEPTED:
                if correlated_id_used:
                    self._response_id_to_client_network_id.pop(
                        response.correlation_response_id
                    )
                else:
                    self._response_id_to_client_network_id.pop(response.id)
            self._client_networks[client_network_id].put_response(response)

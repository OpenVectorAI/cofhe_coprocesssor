from __future__ import annotations

from typing import Dict

import signal
import asyncio

from openvector_cofhe_coprocessor_backend.cli import CliArgs
from openvector_cofhe_coprocessor_backend.common.json_utils import read_json_config
from openvector_cofhe_coprocessor_backend.core.client_network import IClientNetwork
from openvector_cofhe_coprocessor_backend.core.core_service import (
    CoreServiceConfig,
    CoreService,
)
from openvector_cofhe_coprocessor_backend.client_networks.ethereum import (
    EthereumClientConfig,
    EthereumClientNetwork,
)
from openvector_cofhe_coprocessor_backend.core.request_response import ResponseStatus


config_schema = {
    "type": "object",
    "properties": {
        "client_networks": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["ethereum"],
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
                "log_path": {"type": "string"},
                "log_level": {"type": "string"},
            },
            "required": [
                "client_node_ip",
                "client_node_port",
                "setup_node_ip",
                "setup_node_port",
                "cert_path",
                "storage_path",
                "storage_overwrite",
                "log_path",
                "log_level",
            ],
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
    },
    "required": [
        "client_networks",
        "core_service",
    ],
}


class App:
    __slots__ = (
        "_config",
        "_core_service",
        "_client_networks",
        "_cli_args",
        "_response_id_to_client_network_id",
    )

    _config: dict
    _core_service: CoreService
    _client_networks: Dict[str, IClientNetwork]
    _cli_args: CliArgs
    _response_id_to_client_network_id: Dict[str, str]

    def __init__(self, cli_args: CliArgs):
        self._cli_args = cli_args
        self._config = read_json_config(cli_args.config_file_path, config_schema)
        self._response_id_to_client_network_id = {}
        self.__init()

    async def run(self):
        self._start_services()
        while True:
            self._handle_new_requests()
            self._handle_new_responses()
            await asyncio.sleep(0.1)

    def __init(self):
        self._init_core_service()
        self._init_client_networks()
        self._register_signal_handlers()

    def _init_core_service(self):
        self._core_service = CoreService(
            CoreServiceConfig(
                client_node_ip=self._config["core_service"]["client_node_ip"],
                client_node_port=self._config["core_service"]["client_node_port"],
                setup_node_ip=self._config["core_service"]["setup_node_ip"],
                setup_node_port=self._config["core_service"]["setup_node_port"],
                cert_path=self._config["core_service"]["cert_path"],
                storage_path=self._config["core_service"]["storage_path"],
                storage_overwrite=self._config["core_service"]["storage_overwrite"],
                log_path=self._config["core_service"]["log_path"],
                log_level=self._config["core_service"]["log_level"],
            )
        )

    def _init_client_networks(self):
        self._client_networks = {}
        for client_network in self._config["client_networks"]:
            if client_network == "ethereum":
                self._init_ethereum_client_network()
            else:
                raise ValueError(f"Unknown client network: {client_network}")
        if not self._client_networks:
            raise ValueError("No client network configured")

    def _init_ethereum_client_network(self):
        if "ethereum" not in self._config:
            raise ValueError("Ethereum client network is not configured")

        ethereum_config = self._config["ethereum"]
        self._client_networks["ethereum"] = EthereumClientNetwork(
            EthereumClientConfig(
                provider=ethereum_config["provider"],
                contract_address=ethereum_config["contract_address"],
                contract_abi_file_path=ethereum_config["contract_abi_file_path"],
                owner_account_address=ethereum_config["owner_account_address"],
                owner_account_private_key=ethereum_config["owner_account_private_key"],
            )
        )

    def _register_signal_handlers(self):
        signal.signal(signal.SIGINT, self._handle_sigint)
        signal.signal(signal.SIGTERM, self._handle_sigterm)

    def _handle_sigint(self, signum, frame):
        print("Received SIGINT")
        self._stop_services()
        exit(0)

    def _handle_sigterm(self, signum, frame):
        self._stop_services()
        exit(0)

    def _stop_services(self):
        self._core_service.stop()
        for client_network in self._client_networks.values():
            client_network.stop()

    def _start_services(self):
        self._core_service.run()
        for client_network in self._client_networks.values():
            client_network.run()

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
                print(f"Unknown response id: {response.id}")
                continue

            if response.status != ResponseStatus.ACCEPTED:
                if correlated_id_used:
                    self._response_id_to_client_network_id.pop(
                        response.correlation_response_id
                    )
                else:
                    self._response_id_to_client_network_id.pop(response.id)
            self._client_networks[client_network_id].put_response(response)

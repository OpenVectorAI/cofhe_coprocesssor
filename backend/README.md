# Openvector Cofhe Coprocessor Backend

This python module implements the backend for the OpenVector Coprocessor network, ie `openvector_cofhe_coprocessor_backend`.

## Features

- Support for multiple client blockchain networks.
- Support for multiple data availability layers.
- Support for optimistic evaluation of requests for faster response times.
- Uses async architecture for high throughput network operations.

## Installation

To install the backend, run the following command:

```bash
uv sync
```
This will install the backend and all its dependencies.

## Usage

To run the backend, run the following command:

```bash
python -m openvector_cofhe_coprocessor_backend ./artifacts/example_config.local.json
```

Please update the configuration file with the correct values for your environment.

Also the above command should be run from the project virtual environment. To activate the virtual environment, run the following command:

```bash
source ./venv/bin/activate
```
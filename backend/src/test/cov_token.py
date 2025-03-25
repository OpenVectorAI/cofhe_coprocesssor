from __future__ import annotations

import json
from time import sleep
from typing import Tuple
from web3 import Account, Web3, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from web3.contract import Contract
from eth_typing import Address
from web3.types import Wei

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from pycofhe.network import make_cpucryptosystem_client_node, CPUCryptoSystemClientNode
from pycofhe.network import serialize_bitwise, encrypt_bitwise

t_sleep = 10

def set_default_account(w3: Web3, private_key: str) -> None:
    w3.eth.default_account = Account.from_key(private_key)


def submit_mint_request(
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
) -> None:
    print(f"Submitting mint request for {amount} to {recipient} contract {contract.address} confidentially")
    enc_amount = encrypt_bitwise(
        client.cryptosystem, client.network_encryption_key, amount
    )
    ser_amount = serialize_bitwise(client.cryptosystem, enc_amount)
    print(f"Serialized Encrypted Amount: {ser_amount}")
    bytes_amount = bytes(ser_amount, encoding="utf-8")
    contract.functions.mint(recipient, bytes_amount).transact(
        {"from": sender, "value": Wei(15 * 5000000 * 1000000000)}
    )
    print("Mint request submitted")


def submit_transfer_request(
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
) -> None:
    print(f"Submitting transfer request for {amount} to {recipient} contract {contract.address} confidentially")
    enc_amount = encrypt_bitwise(
        client.cryptosystem, client.network_encryption_key, amount
    )
    ser_amount = serialize_bitwise(client.cryptosystem, enc_amount)
    print(f"Serialized Encrypted Amount: {ser_amount}")
    bytes_amount = bytes(ser_amount, encoding="utf-8")
    contract.functions.transfer(recipient, bytes_amount).transact(
        {"from": sender, "value": Wei(24 * 5000000 * 1000000000)}
    )
    print("Transfer request submitted")


def submit_balance_reencryption_request(
    contract: Contract,
    public_key: bytes,
    sender: str,
) -> None:
    try:
        print(f"Submitting balance reencryption request for {sender} contract {contract.address} with public key {public_key.hex()}")
        contract.functions.updateReencryptedBalance(public_key).transact(
            {"from": sender, "value": Wei(5 * 5000000 * 1000000000)}
        )
        print("Balance reencryption request submitted")
    except Exception as e:
        print(f"Failed to get balance: {e}")


def get_balance(contract: Contract, account: str, esk: RsaKey) -> int:
    print(f"Getting balance for {account}")
    enc_bal = contract.functions.reencrypted_balances(account).call({"from": account})
    print(f"Encrypted balance: {enc_bal}")
    cipher = PKCS1_OAEP.new(esk)
    bal = cipher.decrypt(enc_bal)
    int_bal = int.from_bytes(bal, byteorder="big")
    print(f"Decrypted balance: {int_bal}")
    return int_bal


def setup() -> Tuple[Web3, CPUCryptoSystemClientNode, Contract, Account, Account]:
    print("Setting up")
    provider_uri ="http://127.0.0.1:8545"
    contract_address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
    print(f"Connecting to local HTTPProvider at {provider_uri}")
    w3 = Web3(HTTPProvider(provider_uri))
    print("Sleeping for 2 seconds")
    sleep(2)
    print("Checking connection")
    if not w3.is_connected():
        print("Failed to connect to provider")
        exit(1)
    print(f"Connected to {w3.client_version}")
    print(f"Loading contract at {contract_address} and ABI as per given JSON file")
    contract = w3.eth.contract(
        address=contract_address,  # type: ignore
        abi=json.load(
            open(
                "/home/ce/code/openvector/openvector_cofhe_coprocessor/backend/src/test/abi.json"
            )
        ),
    )
    s_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    r_private_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    print(f"Setting default account to {Account.from_key(s_private_key).address}")
    print(f"Using a demo sender account with private key {s_private_key}")
    print(f"Using a demo recipient account with private key {r_private_key}")
    set_default_account(w3, s_private_key)
    # transaction = {
    #     "to": contract.address,
    #     "value": Wei(10*10**18),
    #     "gas": 1000000,
    #     "gasPrice": Wei(5000000000),
    #     "nonce": w3.eth.get_transaction_count(Account.from_key(s_private_key).address),
    #     "chainId": w3.eth.chain_id,
    # }

    # signed_tx = w3.eth.account.sign_transaction(transaction, s_private_key)
    # w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print("Creating a CPU CryptoSystem client node")
    client = make_cpucryptosystem_client_node(
        "127.0.0.1",
        "5587",
        "127.0.0.1",
        "4455",
        "/home/ce/code/openvector/openvector_cofhe_coprocessor/backend/server.pem",
    )
    print("Setup complete")
    return (
        w3,
        client,
        contract,
        Account.from_key(s_private_key),
        Account.from_key(r_private_key),
    )


# def get_public_key(account: Account) -> bytes:
#     # Web3.py Account objects have the public key method
#     return account._key_obj.public_key._raw_key


def rsa_key_pair() -> Tuple[RsaKey, RsaKey]:
    print("Generating RSA key pair for reencryption")
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


def test_mint(w3: Web3, client: CPUCryptoSystemClientNode, contract: Contract, sender: Account, recipient: Account):
    submit_mint_request(client, contract, 100, sender.address, sender.address)
    print(f"Sleeping for {t_sleep} seconds")
    sleep(t_sleep)

    esk, epk = rsa_key_pair()
    submit_balance_reencryption_request(contract, epk.export_key(), sender.address)
    print(f"Sleeping for {t_sleep} seconds")
    sleep(t_sleep)

    # Get balance and assert
    print("Asserting balance")
    assert get_balance(contract, sender.address, esk) == 100


def test_transfer(w3: Web3, client: CPUCryptoSystemClientNode, contract: Contract, sender: Account, recipient: Account):
    submit_transfer_request(client, contract, 100, sender.address, recipient.address)
    print(f"Sleeping for {2*t_sleep} seconds")
    sleep(2*t_sleep)

    essk, espk = rsa_key_pair()
    ersk, erpk = rsa_key_pair()
    submit_balance_reencryption_request(contract, espk.export_key(), sender.address)
    submit_balance_reencryption_request(contract, erpk.export_key(), recipient.address)
    print(f"Sleeping for {t_sleep} seconds")
    sleep(t_sleep)
    
    print("Asserting balance")
    assert get_balance(contract, sender.address, essk) == 0
    assert get_balance(contract, recipient.address, ersk) == 100


def test():
    w3, client, contract, sender, recipient = setup()
    test_mint(w3, client, contract, sender, recipient)
    test_transfer(w3, client, contract, sender, recipient)


if __name__ == "__main__":
    test()

// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "../lib.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "hardhat/console.sol";

contract OVToken is Ownable {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(uint256 totalSupply_) Ownable(msg.sender) {
        totalSupply = 0;
        mint(msg.sender, totalSupply_);
    }

    function transfer(address to, uint256 value) external {
        require(balances[msg.sender] >= value, "Insufficient balance");
        balances[msg.sender] -= value;
        balances[to] += value;
    }

    function mint(address to, uint256 value) public {
        totalSupply += value;
        balances[to] += value;
    }
}

contract COVToken is Ownable {
    CRTT.EUint32 public totalSupply;
    mapping(address => CRTT.EUint32) public balances;
    struct to_from_without_value {
        address to;
        address from;
    }
    mapping(CRTT.RequestID => to_from_without_value)
        public pending_store_requests;
    struct to_from {
        address to;
        address from;
        CRTT.EUint32 value;
    }
    mapping(CRTT.RequestID => to_from) public pending_requests;
    mapping(CRTT.RequestID => to_from) public pending_approval_decision_requests;
    mapping(CRTT.RequestID => address) public pending_reencrypt_requests;
    mapping(CRTT.RequestID => address) public pending_balance_update_requests;
    mapping(address => bytes) public reencrypted_balances;

    constructor() Ownable(msg.sender) {
        totalSupply = CRTT.EUint32.wrap(0);
    }

    function transfer(address to, bytes calldata value) external payable {
        uint128 curr_value_of_sender = CRTT.EUint32.unwrap(balances[msg.sender]);
        require(curr_value_of_sender != 0, "Insufficient balance");
        console.log(
            "Transferring from %s to %s a confidential amount %s",
            msg.sender,
            to,
            string(value)
        );
        store_t(to, value);
    }

    function store_t(address to, bytes calldata value) private {
        console.log(
            "Storing the confidential amount %s in decentralized data layer",
            string(value)
        );
        pending_store_requests[
            COFHE.sendData(
                CRTT.ValueOperand({
                    data_type: CRTT.DataType.UINT32,
                    encryption_scheme: CRTT.OperandEncryptionScheme.CLHSM2k,
                    data: value
                }),
                22 * 5000000 * 1000000000,
                5000000 * 1000000000,
                19 * 5000000 * 1000000000,
                5000000 * 1000000000,
                0,
                this.transfer_i,
                this.dummyStoreResponseCallback
            )
        ] = to_from_without_value({to: to, from: msg.sender});
    }

    function transfer_i(CRTT.DataStoreResponse calldata res) external payable {
        to_from_without_value memory to_from_c = pending_store_requests[
            res.request_id
        ];
        delete pending_store_requests[res.request_id];
        isApprovable(
            to_from_c.to,
            to_from_c.from,
            CRTT.EUint32.wrap(CRTT.DataKey.unwrap(res.result))
        );
    }

    function isApprovable(
        address to,
        address from,
        CRTT.EUint32 value
    ) private {
        console.log(
            "Checking if the transfer is approvable, ie if the sender has enough balance, homomorphically and confidentially"
        );
        pending_requests[
            COFHE.gteq(
                balances[from],
                value,
                18 * 5000000 * 1000000000,
                5000000 * 1000000000,
                15 * 5000000 * 1000000000,
                5000000 * 1000000000,
                0,
                this.isApprovableAccetanceCallback,
                this.dummyCallback
            )
        ] = to_from({to: to, from: from, value: value});
    }

    function isApprovableAccetanceCallback(
        CRTT.Response calldata res
    ) external payable {
        CRTT.DataKey key = CRTT.DataKey.wrap(
            // abi.decode(res.result.data, (uint128))
            (uint128)(bytes16(res.result.data))
        );
        pending_approval_decision_requests[
            COFHE.retrieveData(
                key,
                CRTT.DataRequestedType.DECRYPTED,
                14 * 5000000 * 1000000000,
                5000000 * 1000000000,
                9 * 5000000 * 1000000000,
                this.isApprovableRetreiveDataAccetanceCallback,
                bytes("")
            )
        ] = pending_requests[res.request_id];
        delete pending_requests[res.request_id];
    }

    function isApprovableRetreiveDataAccetanceCallback(
        CRTT.DataRetrievalResponse calldata res
    ) external payable {
        console.log("Calculated approvable status");
        // uint8 decrypted = abi.decode(res.result.data, (uint8));
        uint256 decrypted = uint256(bytes32(res.result.data));
        // require decrypted == 1, "Insufficient balance";
        if (decrypted != 0) {
            console.log(
                "Transfer is approved, transferring the confidential amount"
            );
            address from = pending_approval_decision_requests[res.request_id].from;
            address to = pending_approval_decision_requests[res.request_id].to;
            CRTT.EUint32 value = pending_approval_decision_requests[res.request_id].value;
            uint128 curr_value_of_recv = CRTT.EUint32.unwrap(balances[to]);
            if (curr_value_of_recv == 0) {
                balances[to] = value;
            } else {
                pending_balance_update_requests[
                    COFHE.add(
                        balances[to],
                        value,
                        4 * 5000000 * 1000000000,
                        5000000 * 1000000000,
                        0,
                        5000000 * 1000000000,
                        0,
                        this.updateBalanceCallback,
                        this.dummyCallback
                    )
                ] = to;
            }
            pending_balance_update_requests[
                COFHE.sub(
                    balances[from],
                    value,
                    4 * 5000000 * 1000000000,
                    5000000 * 1000000000,
                    0,
                    5000000 * 1000000000,
                    0,
                    this.updateBalanceCallback,
                    this.dummyCallback
                )
            ] = from;
        } else {
            console.log("Transfer is not approved, insufficient balance");
        }
        delete pending_approval_decision_requests[res.request_id];
    }

    function mint(address to, bytes memory value) public payable {
        console.log("Minting confidential amount %s to %s", string(value), to);
        store_m(to, value);
    }

    function store_m(address to, bytes memory value) private {
        console.log(
            "Storing the confidential amount %s in decentralized data layer",
            string(value)
        );
        pending_store_requests[
            COFHE.sendData(
                CRTT.ValueOperand({
                    data_type: CRTT.DataType.UINT32,
                    encryption_scheme: CRTT.OperandEncryptionScheme.CLHSM2k,
                    data: value
                }),
                14 * 5000000 * 1000000000,
                5000000 * 1000000000,
                9 * 5000000 * 1000000000,
                5000000 * 1000000000,
                0,
                this.mint_i,
                this.dummyStoreResponseCallback
            )
        ] = to_from_without_value({to: to, from: msg.sender});
    }

    function mint_i(CRTT.DataStoreResponse calldata res) external payable {
        to_from_without_value memory to_from_c = pending_store_requests[
            res.request_id
        ];
        delete pending_store_requests[res.request_id];
        address to = to_from_c.to;
        CRTT.EUint32 value = CRTT.EUint32.wrap(CRTT.DataKey.unwrap(res.result));
        if (CRTT.EUint32.unwrap(totalSupply) == 0) {
            totalSupply = value;
            balances[to] = value;
            console.log(
                "Minting completed, balance key for %s is %d",
                to,
                CRTT.EUint32.unwrap(balances[to])
            );
        } else {
            console.log("Adding the minted amount to the total supply");
            COFHE.add(
                totalSupply,
                value,
                4 * 5000000 * 1000000000,
                5000000 * 1000000000,
                0,
                5000000 * 1000000000,
                0,
                this.updateTotalSupplyCallback,
                this.dummyCallback
            );
            CRTT.EUint32 c_balance = balances[to];
            if (CRTT.EUint32.unwrap(c_balance) == 0) {
                console.log(
                    "Allocated required tokens to the minter %s, the balance key is %d",
                    to,
                    CRTT.EUint32.unwrap(value)
                );
                balances[to] = value;
            } else {
                console.log(
                    "Adding the minted amount to the existing balance of the minter %s",
                    to
                );
                pending_balance_update_requests[
                    COFHE.add(
                        balances[to],
                        value,
                        4 * 5000000 * 1000000000,
                        5000000 * 1000000000,
                        0,
                        5000000 * 1000000000,
                        0,
                        this.updateBalanceCallback,
                        this.dummyCallback
                    )
                ] = to;
            }
        }
    }

    function updateReencryptedBalance(bytes calldata pubkey) external payable {
        uint128 curr_value_of_sender = CRTT.EUint32.unwrap(balances[msg.sender]);
        require(curr_value_of_sender != 0, "No account found");
        console.log(
            "Updating reencrypted balance for %s with pubkey %s",
            msg.sender,
            string(pubkey)
        );
        pending_reencrypt_requests[
            COFHE.retrieveData(
                CRTT.DataKey.wrap(CRTT.EUint32.unwrap(balances[msg.sender])),
                CRTT.DataRequestedType.REENCRYPTED,
                2 * 5000000 * 1000000000,
                5000000 * 1000000000,
                0,
                this.updateReencryptedBalanceCallback,
                pubkey
            )
        ] = msg.sender;
    }

    function updateReencryptedBalanceCallback(
        CRTT.DataRetrievalResponse calldata res
    ) external payable {
        console.log("Storing the reencrypted balance");
        reencrypted_balances[pending_reencrypt_requests[res.request_id]] = res
            .result
            .data;
        console.log(
            "Successfully stored the updated reencrypted balance for %s",
            pending_reencrypt_requests[res.request_id]
        );
        delete pending_reencrypt_requests[res.request_id];
    }

    function updateBalanceCallback(
        CRTT.Response calldata res
    ) external payable {
        console.log("Updating the balance");
        address to = pending_balance_update_requests[res.request_id];
        delete pending_balance_update_requests[res.request_id];
        balances[to] = CRTT.EUint32.wrap(
            // abi.decode(res.result.data, (uint128))
            (uint128)(bytes16(res.result.data))
        );

        console.log(
            "For the address %s the new balance key is %d",
            pending_balance_update_requests[res.request_id],
            (uint128)(bytes16(res.result.data))
        );
    }

    function updateTotalSupplyCallback(
        CRTT.Response calldata res
    ) external payable {
        console.log("Updating the total supply");
        totalSupply = CRTT.EUint32.wrap(
            // abi.decode(res.result.data, (uint128))
            (uint128)(bytes16(res.result.data))
        );
        console.log(
            "The new total supply is %d",
            CRTT.EUint32.unwrap(totalSupply)
        );
    }

    function dummyCallback(CRTT.Response calldata res) external payable {
        console.log("This is a dummy callback, no action is required");
    }

    function dummyStoreResponseCallback(
        CRTT.DataStoreResponse calldata res
    ) external payable {
        console.log(
            "This is a dummy store response callback, no action is required"
        );
    }

    // Accept Ether without any data (the receive function is automatically called)
    receive() external payable {
        // Custom logic for handling received Ether (optional)
    }

    // Optionally, you can also have a fallback function
    fallback() external payable {
        // Custom logic for handling received Ether (optional)
    }
}

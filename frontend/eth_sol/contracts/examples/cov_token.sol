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
    uint256 constant N_BASE_PAYMENT = 163000 * 1000000000;
    uint256 constant O_BASE_PAYMENT = 1000;
    uint256 constant BASE_PAYMENT = N_BASE_PAYMENT + O_BASE_PAYMENT;
    uint256 constant PAYMENT_CALLBACK_PAYMENT = 30000 * 1000000000;
    uint256 constant TRANSFER_FUNC_CALLBACK_PAYMENT = 80000 * 1000000000;
    uint256 constant TRANSFER_FUNC_PAYMENT =
        BASE_PAYMENT +
            TRANSFER_FUNC_CALLBACK_PAYMENT +
            PAYMENT_CALLBACK_PAYMENT;
    uint256 constant MINT_FUNC_CALLBACK_PAYMENT = 60000 * 1000000000;
    uint256 constant MINT_FUNC_PAYMENT =
        BASE_PAYMENT + MINT_FUNC_CALLBACK_PAYMENT + PAYMENT_CALLBACK_PAYMENT;
    uint256 constant UPDATE_REENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT =
        2000000 * 1000000000;
    uint256 constant UPDATE_REENCRYPTED_BALANCE_FUNC_PAYMENT =
        BASE_PAYMENT +
            UPDATE_REENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT +
            PAYMENT_CALLBACK_PAYMENT;
    uint256 constant UPDATE_ENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT =
        200000 * 1000000000;
    uint256 constant UPDATE_ENCRYPTED_BALANCE_FUNC_PAYMENT =
        BASE_PAYMENT +
            UPDATE_ENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT +
            PAYMENT_CALLBACK_PAYMENT;
    uint256 constant REGISTER_KEY_FUNC_ACCEPTANCE_CALLBACK_PAYMENT =
        30000 * 1000000000;
    uint256 constant REGISTER_KEY_FUNC_SUBMISSION_CALLBACK_PAYMENT =
        100000 * 1000000000;
    uint256 constant REGISTER_KEY_FUNC_PAYMENT =
        BASE_PAYMENT +
            REGISTER_KEY_FUNC_ACCEPTANCE_CALLBACK_PAYMENT +
            REGISTER_KEY_FUNC_SUBMISSION_CALLBACK_PAYMENT +
            PAYMENT_CALLBACK_PAYMENT;

    CRTT.EUint32 public totalSupply;
    mapping(address => CRTT.EUint32) public balances;
    struct to_from {
        address to;
        address payable from;
    }
    bool minting = false;
    mapping(CRTT.RequestID => address payable) public pending_mint_requests;
    mapping(address => bool) transfer_in_progress;
    mapping(CRTT.RequestID => to_from) public pending_transfer_requests;
    mapping(CRTT.RequestID => address payable) register_requests;
    mapping(address => CRTT.DataKey) public registered_keys;
    mapping(CRTT.RequestID => address payable)
        public pending_reencrypt_requests;
    mapping(address => bytes) public encrypted_balances;
    mapping(address => bytes) public reencrypted_balances;

    address[] registered_users;
    uint256 total_registered_users = 0;

    constructor() Ownable(msg.sender) {
        totalSupply = CRTT.getUintializedEUint32();
    }

    function transfer(address to, bytes calldata value) external payable {
        require(!transfer_in_progress[msg.sender], "Transfer in progress");
        transfer_in_progress[msg.sender] = true;
        transfer_in_progress[to] = true;
        // this means that user have 0 balance
        require(
            CRTT.isEUint32Initialized(balances[msg.sender]),
            "Insufficient balance"
        );
        console.log(
            "Transferring from %s to %s a confidential amount %s",
            msg.sender,
            to,
            string(value)
        );
        pending_transfer_requests[
            COFHE.doConfidentialCoinCalculation(
                TRANSFER_FUNC_PAYMENT,
                false,
                balances[msg.sender],
                balances[to],
                value,
                TRANSFER_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.transferCallback,
                this.transfePaymentCallback
            )
        ] = to_from({to: to, from: payable(msg.sender)});
    }

    function transferCallback(
        CRTT.ConfidentialCoinResponse calldata res
    ) external payable {
        console.log("Transfer acceptance callback");
        if (res.status != CRTT.ResponseStatus.SUCCESS) {
            console.log("Transfer failed due to an error");
            return;
        }
        if (res.success) {
            to_from memory to_from_c = pending_transfer_requests[
                res.request_id
            ];
            balances[to_from_c.to] = res.receiver_balance;
            balances[to_from_c.from] = res.sender_balance;
            console.log(
                "Successfully transferred the confidential amount from %s to %s",
                to_from_c.from,
                to_from_c.to
            );
            console.log(
                "The new balance key for %s is %d",
                to_from_c.to,
                CRTT.eUint32ToUint128(res.receiver_balance)
            );
            console.log(
                "The new balance key for %s is %d",
                to_from_c.from,
                CRTT.eUint32ToUint128(res.sender_balance)
            );
        } else {
            console.log("Transfer failed due to insufficient balance");
        }
    }

    function transfePaymentCallback(
        CRTT.RequestID request_id
    ) external payable {
        console.log("Transfer payment callback");
        transfer_in_progress[
            pending_transfer_requests[request_id].from
        ] = false;
        transfer_in_progress[pending_transfer_requests[request_id].to] = false;
        pending_transfer_requests[request_id].from.transfer(msg.value);
        delete pending_transfer_requests[request_id];
    }

    function mint(address to, bytes memory value) public payable {
        require(!minting, "Mint in progress");
        minting = true;
        console.log("Minting confidential amount %s to %s", string(value), to);
        pending_mint_requests[
            COFHE.doConfidentialCoinCalculation(
                MINT_FUNC_PAYMENT,
                true,
                totalSupply,
                balances[to],
                value,
                MINT_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.mintCallback,
                this.mintPaymentCallback
            )
        ] = payable(to);
    }

    function mintCallback(
        CRTT.ConfidentialCoinResponse calldata res
    ) external payable {
        console.log("Mint acceptance callback");
        if (res.status != CRTT.ResponseStatus.SUCCESS) {
            console.log("Mint failed due to an error");
            return;
        }
        if (res.success) {
            address to = pending_mint_requests[res.request_id];
            balances[to] = res.receiver_balance;
            totalSupply = res.sender_balance;
            console.log(
                "Successfully minted the confidential amount to %s",
                to
            );
            console.log(
                "The new balance key for %s is %d",
                to,
                CRTT.eUint32ToUint128(res.receiver_balance)
            );
            console.log(
                "The new total supply is %d",
                CRTT.eUint32ToUint128(res.sender_balance)
            );
        } else {
            console.log("Mint failed due to insufficient balance");
        }
    }

    function mintPaymentCallback(CRTT.RequestID request_id) external payable {
        console.log("Mint payment callback");
        minting = false;
        pending_mint_requests[request_id].transfer(msg.value);
        delete pending_mint_requests[request_id];
    }

    function updateReencryptedBalance() external payable {
        require(
            CRTT.isDataKeyValid(registered_keys[msg.sender]),
            "User not registered"
        );
        require(!transfer_in_progress[msg.sender], "Transfer in progress");
        require(
            CRTT.isEUint32Initialized(balances[msg.sender]),
            "Insufficient balance"
        );
        console.log(
            "Updating reencrypted balance for %s with pubkey %d",
            msg.sender,
            CRTT.dataKeyToUint128(registered_keys[msg.sender])
        );
        pending_reencrypt_requests[
            COFHE.retrieveData(
                CRTT.eUint32ToDataKey(balances[msg.sender]),
                CRTT.DataRequestedType.REENCRYPTED,
                UPDATE_REENCRYPTED_BALANCE_FUNC_PAYMENT,
                UPDATE_REENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.updateReencryptedBalanceCallback,
                this.updateReencryptedBalancePaymentCallback,
                registered_keys[msg.sender]
            )
        ] = payable(msg.sender);
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
    }

    function updateReencryptedBalancePaymentCallback(
        CRTT.RequestID request_id
    ) external payable {
        console.log("Update reencrypted balance payment callback");
        pending_reencrypt_requests[request_id].transfer(msg.value);
        delete pending_reencrypt_requests[request_id];
    }

    function updateEncryptedBalance() external payable {
        require(
            CRTT.isDataKeyValid(registered_keys[msg.sender]),
            "User not registered"
        );
        require(!transfer_in_progress[msg.sender], "Transfer in progress");
        require(
            CRTT.isEUint32Initialized(balances[msg.sender]),
            "Insufficient balance"
        );
        console.log(
            "Updating encrypted balance for %s with pubkey %d",
            msg.sender,
            CRTT.dataKeyToUint128(registered_keys[msg.sender])
        );
        pending_reencrypt_requests[
            COFHE.retrieveData(
                CRTT.eUint32ToDataKey(balances[msg.sender]),
                CRTT.DataRequestedType.ENCRYPTED,
                UPDATE_ENCRYPTED_BALANCE_FUNC_PAYMENT,
                UPDATE_ENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.updateEncryptedBalanceCallback,
                this.updateEncryptedBalancePaymentCallback,
                registered_keys[msg.sender]
            )
        ] = payable(msg.sender);
    }

    function updateEncryptedBalanceCallback(
        CRTT.DataRetrievalResponse calldata res
    ) external payable {
        console.log("Storing the encrypted balance");
        encrypted_balances[pending_reencrypt_requests[res.request_id]] = res
            .result
            .data;
        console.log(
            "Successfully stored the updated encrypted balance for %s",
            pending_reencrypt_requests[res.request_id]
        );
    }

    function updateEncryptedBalancePaymentCallback(
        CRTT.RequestID request_id
    ) external payable {
        console.log("Update encrypted balance payment callback");
        pending_reencrypt_requests[request_id].transfer(msg.value);
        delete pending_reencrypt_requests[request_id];
    }

    function registerKey(bytes calldata public_key) external payable {
        if (CRTT.isDataKeyValid(registered_keys[msg.sender])) {
            console.log(
                "User %s already registered with pubkey %d",
                msg.sender,
                CRTT.dataKeyToUint128(registered_keys[msg.sender])
            );
            console.log("Updating the public key");
        }
        register_requests[
            COFHE.sendData(
                CRTT.ValueOperand(
                    CRTT.DataType.RSA_PUBLIC_KEY,
                    CRTT.OperandEncryptionScheme.NONE,
                    public_key
                ),
                REGISTER_KEY_FUNC_PAYMENT,
                REGISTER_KEY_FUNC_ACCEPTANCE_CALLBACK_PAYMENT,
                REGISTER_KEY_FUNC_SUBMISSION_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.registerKeyCallback,
                this.registerKeySubmissionCallback,
                this.registerKeyPaymentCallback
            )
        ] = payable(msg.sender);
        console.log(
            "Registering the public key for %s with pubkey %s",
            msg.sender,
            string(public_key)
        );
    }

    function registerKeyCallback(
        CRTT.DataStoreResponse calldata res
    ) external payable {
        console.log("Register key callback");
        if (res.status != CRTT.ResponseStatus.ACCEPTED) {
            console.log(
                "This should not happen, errors are supposed to go to submission callback"
            );
            return;
        }
        registered_keys[register_requests[res.request_id]] = res.result;

        console.log(
            "Successfully registered the public key for %s with pubkey %d",
            msg.sender,
            CRTT.dataKeyToUint128(res.result)
        );
    }

    function registerKeySubmissionCallback(
        CRTT.DataStoreResponse calldata res
    ) external payable {
        registered_users.push(register_requests[res.request_id]);
        total_registered_users++;
        console.log("Register key submission callback");
        if (res.status != CRTT.ResponseStatus.SUCCESS) {
            console.log(
                "Key registration for request id %d and user %s failed",
                CRTT.requestIDToUint128(res.request_id),
                register_requests[res.request_id]
            );
            return;
        }
    }

    function registerKeyPaymentCallback(
        CRTT.RequestID request_id
    ) external payable {
        console.log("Register key payment callback");
        register_requests[request_id].transfer(msg.value);
        delete register_requests[request_id];
    }

    function getBalance() external view returns (CRTT.EUint32) {
        return balances[msg.sender];
    }

    function getReencryptedBalance() external view returns (bytes memory) {
        return reencrypted_balances[msg.sender];
    }

    function getRegisteredKey() external view returns (CRTT.DataKey) {
        return registered_keys[msg.sender];
    }

    function getTotalSupply() external view returns (CRTT.EUint32) {
        return totalSupply;
    }

    function getBalanceOf(address user) external view returns (CRTT.EUint32) {
        return balances[user];
    }

    function getReencryptedBalanceOf(
        address user
    ) external view returns (bytes memory) {
        return reencrypted_balances[user];
    }

    function getRegisteredKeyOf(
        address user
    ) external view returns (CRTT.DataKey) {
        return registered_keys[user];
    }

    function getMintingInProgress() external view returns (bool) {
        return minting;
    }

    function getTransferInProgress() external view returns (bool) {
        return transfer_in_progress[msg.sender];
    }

    function getTransferInProgressOf(
        address user
    ) external view returns (bool) {
        return transfer_in_progress[user];
    }

    // debug funcs
    function setMinting(bool minting_) external onlyOwner {
        minting = minting_;
    }

    function setTransferInProgress(
        address user,
        bool transfer_in_progress_
    ) external onlyOwner {
        transfer_in_progress[user] = transfer_in_progress_;
    }

    function setRegisteredKey(
        address user,
        CRTT.DataKey public_key
    ) external onlyOwner {
        registered_keys[user] = public_key;
    }

    function setEncryptedBalance(
        address user,
        bytes memory encrypted_balance
    ) external onlyOwner {
        encrypted_balances[user] = encrypted_balance;
    }

    function setReencryptedBalance(
        address user,
        bytes memory reencrypted_balance
    ) external onlyOwner {
        reencrypted_balances[user] = reencrypted_balance;
    }

    function setBalance(address user, CRTT.EUint32 balance) external onlyOwner {
        balances[user] = balance;
    }

    function setTotalSupply(CRTT.EUint32 total_supply) external onlyOwner {
        totalSupply = total_supply;
    }

    function reset_contract() external onlyOwner {
        minting = false;
        for (uint256 i = 0; i < total_registered_users; i++) {
            registered_keys[registered_users[i]] = CRTT.getInvalidDataKey();
            delete transfer_in_progress[registered_users[i]];
            balances[registered_users[i]] = CRTT.getUintializedEUint32();
            delete encrypted_balances[registered_users[i]];
            delete reencrypted_balances[registered_users[i]];
        }
        for (uint256 i = 0; i < total_registered_users; i++) {
            delete registered_users[i];
        }
        totalSupply = CRTT.getUintializedEUint32();
        total_registered_users = 0;
    }

    receive() external payable {}

    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}

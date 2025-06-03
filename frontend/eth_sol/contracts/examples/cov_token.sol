// SPDX-License-Identifier: BSD-3-Clause

pragma solidity ^0.8.0;

import "../lib.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "hardhat/console.sol";

/**
 * @title OVToken
 * @dev A simple ERC20 token with a publicly callable mint function.
 * WARNING: A public mint function is generally unsafe for tokens intended to have value.
 * This is for demonstration purposes only. And is used in demonstration of
 * COVToken contract.
 */
contract OVToken is ERC20 {
    constructor() ERC20("OVToken", "OVT") {}

    /**
     * @notice Creates `amount` tokens and assigns them to `to`, increasing
     * the total supply.
     * @dev This function is PUBLICLY CALLABLE. Anyone can mint tokens.
     * This is highly insecure for a token with real value.
     * @param to The address that will receive the minted tokens.
     * @param amount The amount of tokens to mint.
     */
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

/**
 * @title COVToken
 * @dev A simple confidential token contract that uses the COFHE library for
 * confidential operations. It allows users to mint, transfer, and query
 * their balances in a confidential manner.
 * WARNING: This contract is for demonstration purposes only and should not
 * be used in production without proper security audits and testing.
 */

contract COVToken is Ownable {
    address public constant TOKEN_CONTRACT =
        0x3CEa0f53909E8Ef1Dbd86E59D50aDe14A6819107;
    // 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

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
    uint256 constant UNWRAP_TO_ETH_FUNC_CALLBACK_PAYMENT = 60000 * 1000000000;
    uint256 constant UNWRAP_TO_ETH_FUNC_PAYMENT =
        BASE_PAYMENT +
            UNWRAP_TO_ETH_FUNC_CALLBACK_PAYMENT +
            PAYMENT_CALLBACK_PAYMENT;

    IERC20 public immutable ACCEPTED_TOKEN = IERC20(TOKEN_CONTRACT);
    // 1 OVToken = 1 COVToken
    uint256 public ov_token_to_cov_token_ratio = 1;
    // 1000000gwei = 1 COVToken
    uint256 public eth_to_cov_token_ratio = 1000_000_000_000_000;

    CRTT.EUint32 public totalSupply;
    mapping(address => CRTT.EUint32) public balances;
    struct to_from {
        address to;
        address payable from;
    }
    struct unwrap_to {
        address payable to;
        uint256 amount;
    }
    bool computing = false;
    mapping(CRTT.RequestID => address payable) public pending_mint_requests;
    mapping(CRTT.RequestID => unwrap_to) public pending_unwrap_to_eth_requests;
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

    function lockContract() internal {
        require(!computing, "Computing in progress");
        computing = true;
    }

    function unlockContract() internal {
        require(computing, "Contract is not locked");
        computing = false;
    }

    function transfer(address to, bytes calldata value) external payable {
        lockContract();
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
        bytes[] memory empty_acl = new bytes[](0);
        bytes[] memory receiver_acl = new bytes[](2);
        if (CRTT.isEUint32Initialized(balances[to]) == false) {
            console.log("Receiver %s is not registered", to);
            receiver_acl[0] = abi.encodePacked(address(this));
            receiver_acl[1] = abi.encodePacked(to);
        }
        pending_transfer_requests[
            COFHE.doConfidentialCoinCalculation(
                TRANSFER_FUNC_PAYMENT,
                false,
                balances[msg.sender],
                balances[to],
                0,
                value,
                false,
                empty_acl,
                receiver_acl,
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
        unlockContract();
        pending_transfer_requests[request_id].from.transfer(msg.value);
        delete pending_transfer_requests[request_id];
    }

    function mintFromOVToken(address to, uint256 amount) external payable {
        lockContract();
        console.log("Minting %d to %s", amount, to);
        console.log(
            "At the rate of %d OVToken to 1 COVToken",
            ov_token_to_cov_token_ratio
        );
        require(
            ACCEPTED_TOKEN.balanceOf(msg.sender) >=
                amount * ov_token_to_cov_token_ratio,
            "Insufficient balance"
        );
        require(
            ACCEPTED_TOKEN.allowance(msg.sender, address(this)) >=
                amount * ov_token_to_cov_token_ratio,
            "Insufficient allowance"
        );
        require(
            ACCEPTED_TOKEN.transferFrom(
                msg.sender,
                address(this),
                amount * ov_token_to_cov_token_ratio
            ),
            "Transfer failed"
        );
        bytes[] memory total_amount_acl = new bytes[](2);
        bytes memory contract_address = abi.encodePacked(address(this));
        total_amount_acl[0] = contract_address;
        total_amount_acl[1] = bytes("");
        bytes[] memory minter_acl = new bytes[](2);
        minter_acl[0] = contract_address;
        minter_acl[1] = abi.encodePacked(msg.sender);
        pending_mint_requests[
            COFHE.doConfidentialCoinCalculation(
                MINT_FUNC_PAYMENT,
                true,
                totalSupply,
                balances[to],
                amount,
                bytes(""),
                false,
                total_amount_acl,
                minter_acl,
                MINT_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.mintCallback,
                this.mintPaymentCallback
            )
        ] = payable(to);
    }

    function mintFromEth(address to, uint256 amount) external payable {
        lockContract();
        console.log("Minting %d to %s", amount, to);
        console.log(
            "At the rate of %d eth to 1 COVToken",
            eth_to_cov_token_ratio
        );
        require(
            msg.value >= amount * eth_to_cov_token_ratio + MINT_FUNC_PAYMENT,
            "Insufficient balance"
        );
        bytes[] memory total_amount_acl = new bytes[](2);
        bytes memory contract_address = abi.encodePacked(address(this));
        total_amount_acl[0] = contract_address;
        total_amount_acl[1] = bytes("");
        bytes[] memory minter_acl = new bytes[](2);
        minter_acl[0] = contract_address;
        minter_acl[1] = abi.encodePacked(msg.sender);
        pending_mint_requests[
            COFHE.doConfidentialCoinCalculation(
                MINT_FUNC_PAYMENT,
                true,
                totalSupply,
                balances[to],
                amount,
                bytes(""),
                false,
                total_amount_acl,
                minter_acl,
                MINT_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.mintCallback,
                this.mintPaymentCallback
            )
        ] = payable(to);
    }

    function mint(address to, bytes memory value) public payable {
        lockContract();
        console.log("Minting confidential amount %s to %s", string(value), to);
        bytes[] memory total_amount_acl = new bytes[](2);
        bytes memory contract_address = abi.encodePacked(address(this));
        total_amount_acl[0] = contract_address;
        total_amount_acl[1] = bytes("");
        bytes[] memory minter_acl = new bytes[](2);
        minter_acl[0] = contract_address;
        minter_acl[1] = abi.encodePacked(msg.sender);
        pending_mint_requests[
            COFHE.doConfidentialCoinCalculation(
                MINT_FUNC_PAYMENT,
                true,
                totalSupply,
                balances[to],
                0,
                value,
                false,
                total_amount_acl,
                minter_acl,
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
        unlockContract();
        pending_mint_requests[request_id].transfer(msg.value);
        delete pending_mint_requests[request_id];
    }

    function unwrapFromCOVTokenForEth(uint256 amount) external payable {
        lockContract();
        require(
            msg.value >= MINT_FUNC_PAYMENT,
            "Insufficient balance for payment"
        );
        require(
            CRTT.isEUint32Initialized(balances[msg.sender]),
            "Insufficient balance"
        );
        console.log(
            "Unwrapping %d COVToken to ETH",
            amount * eth_to_cov_token_ratio
        );
        require(
            amount * eth_to_cov_token_ratio <= address(this).balance,
            "COVToken balance is not enough"
        );
        console.log(
            "Unwrapping %d COVToken to OVToken",
            amount * ov_token_to_cov_token_ratio
        );
        bytes[] memory empty_acl = new bytes[](0);
        pending_unwrap_to_eth_requests[
            COFHE.doConfidentialCoinCalculation(
                UNWRAP_TO_ETH_FUNC_PAYMENT,
                true,
                totalSupply,
                balances[msg.sender],
                amount,
                bytes(""),
                true,
                empty_acl,
                empty_acl,
                UNWRAP_TO_ETH_FUNC_CALLBACK_PAYMENT,
                PAYMENT_CALLBACK_PAYMENT,
                this.unwrapToEthCallback,
                this.unwrapToEthPaymentCallback
            )
        ] = unwrap_to({
            to: payable(msg.sender),
            amount: amount * eth_to_cov_token_ratio
        });
    }

    function unwrapToEthCallback(
        CRTT.ConfidentialCoinResponse calldata res
    ) external payable {
        console.log("Unwrap to ETH acceptance callback");
        if (res.status != CRTT.ResponseStatus.SUCCESS) {
            console.log("Unwrap failed due to an error");
            return;
        }
        if (res.success) {
            address payable to = pending_unwrap_to_eth_requests[res.request_id]
                .to;
            uint256 amount = pending_unwrap_to_eth_requests[res.request_id]
                .amount;
            require(
                amount <= address(this).balance,
                "COVToken balance is not enough"
            );
            balances[to] = res.receiver_balance;
            totalSupply = res.sender_balance;
            to.transfer(amount);
            console.log(
                "Successfully unwrapped the confidential amount to %s and sent %d ETH",
                to,
                amount
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
            console.log("Unwrap failed due to insufficient balance");
        }
    }

    function unwrapToEthPaymentCallback(
        CRTT.RequestID request_id
    ) external payable {
        console.log("Unwrap to ETH payment callback");
        unlockContract();
        pending_unwrap_to_eth_requests[request_id].to.transfer(msg.value);
        delete pending_unwrap_to_eth_requests[request_id];
    }

    function updateReencryptedBalance() external payable {
        require(
            CRTT.isDataKeyValid(registered_keys[msg.sender]),
            "User not registered"
        );
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

    function getComputing() external view returns (bool) {
        return computing;
    }

    function setOVTokenToCOVTokenRatio(uint256 ratio) external onlyOwner {
        ov_token_to_cov_token_ratio = ratio;
    }

    function setEthToCOVTokenRatio(uint256 ratio) external onlyOwner {
        eth_to_cov_token_ratio = ratio;
    }

    function getOVTokenToCOVTokenRatio() external view returns (uint256) {
        return ov_token_to_cov_token_ratio;
    }

    function getEthToCOVTokenRatio() external view returns (uint256) {
        return eth_to_cov_token_ratio;
    }

    // debug funcs
    function setComputing(bool _computing) external onlyOwner {
        computing = _computing;
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

    function setComputingValue(bool value) external onlyOwner {
        computing = value;
    }

    function reset_contract() external onlyOwner {
        computing = true;
        console.log("Resetting the contract");
        for (uint256 i = 0; i < total_registered_users; i++) {
            registered_keys[registered_users[i]] = CRTT.getInvalidDataKey();
            balances[registered_users[i]] = CRTT.getUintializedEUint32();
            delete encrypted_balances[registered_users[i]];
            delete reencrypted_balances[registered_users[i]];
        }
        for (uint256 i = 0; i < total_registered_users; i++) {
            delete registered_users[i];
        }
        totalSupply = CRTT.getUintializedEUint32();
        total_registered_users = 0;
        unlockContract();
    }

    receive() external payable {}

    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}

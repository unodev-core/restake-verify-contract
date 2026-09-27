// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {DeadlineGuard} from "./DeadlineGuard.sol";
import {IAllowlistRegistry} from "./interfaces/IAllowlistRegistry.sol";
import {AaveRules} from "./libraries/AaveRules.sol";
import {AccountCallDecoder} from "./libraries/AccountCallDecoder.sol";
import {AllowanceRules} from "./libraries/AllowanceRules.sol";
import {BatchLayout, Layout, MainResult} from "./libraries/BatchLayout.sol";
import {BridgeRules} from "./libraries/BridgeRules.sol";
import {CallLib} from "./libraries/CallLib.sol";
import {Erc4626Rules} from "./libraries/Erc4626Rules.sol";
import {FeeRules} from "./libraries/FeeRules.sol";
import {SwapRules} from "./libraries/SwapRules.sol";
import {UserOpLib} from "./libraries/UserOpLib.sol";
import {NO_INDEX, Reason, Rejected, reject} from "./types/Errors.sol";
import {Action, Authorization, Call, Category, Config, Intent, PackedUserOperation} from "./types/Types.sol";

/// @title BatchVerifier
/// @notice Read-only verifier partners call with `eth_call` on their own node before the user signs a Restake
///         EIP-7702 batch user operation. Answers: does this exact op do only what the user asked for, touching only
///         allowlisted contracts, and is this the hash about to be signed? Default deny.
/// @dev Logic only. The only state is the registry pointer. Upgrades go through the 48 h TimelockController.
contract BatchVerifier is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    /// @notice EntryPoint v0.7, same address on every chain (§2.1).
    address public constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    /// @notice Alchemy Modular Account v2, 7702 variant, same address on every chain (§2.1).
    address public constant MAV2_7702_IMPL = 0x69007702764179f14F51cdce752f4f775d74E139;

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable DEADLINE_GUARD;

    /// @custom:storage-location erc7201:restake.storage.BatchVerifier
    struct VerifierStorage {
        IAllowlistRegistry registry;
    }

    // keccak256(abi.encode(uint256(keccak256("restake.storage.BatchVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_LOCATION = 0xde8c419ae14061a8b03d9e5e5d9509e524c66f7c4f0661c9780d2ce913990e00;

    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address deadlineGuard) {
        if (deadlineGuard == address(0)) revert ZeroAddress();
        DEADLINE_GUARD = deadlineGuard;
        _disableInitializers();
    }

    /// @param admin DEFAULT_ADMIN_ROLE holder. Must be the TimelockController.
    /// @param upgrader UPGRADER_ROLE holder. Must be the TimelockController.
    function initialize(IAllowlistRegistry registry_, address admin, address upgrader) external initializer {
        if (address(registry_) == address(0) || admin == address(0) || upgrader == address(0)) revert ZeroAddress();
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, upgrader);
        _s().registry = registry_;
    }

    function registry() public view returns (IAllowlistRegistry) {
        return _s().registry;
    }

    /// @notice Verify `op` against the user's intent.
    /// @return verifiedHash The v0.7 userOpHash the wallet must sign (EIP-191 over the raw 32 bytes, `0xff00` prefix).
    /// @return deadline The in-batch deadline; the op cannot execute after it.
    /// @dev Reverts with `Rejected(reason, callIndex)` on any rule violation.
    function verify(
        PackedUserOperation calldata op,
        bytes32 userOpHash,
        Authorization calldata auth,
        Intent calldata intent
    ) external view returns (bytes32 verifiedHash, uint256 deadline) {
        IAllowlistRegistry reg = _s().registry;
        if (reg.paused()) reject(Reason.PAUSED, NO_INDEX);
        Config memory cfg = reg.config();

        verifiedHash = _checkEnvelope(op, userOpHash, auth, intent, reg, cfg);
        Call[] memory calls = AccountCallDecoder.decode(op.callData);
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].target == op.sender) reject(Reason.SELF_CALL_FORBIDDEN, i);
            if (calls[i].value != 0) reject(Reason.NATIVE_VALUE, i);
        }
        deadline = _checkDeadline(calls, cfg);
        _checkActions(calls, intent, reg, cfg);
    }

    /// @notice Non-reverting variant of `verify` for UIs.
    /// @return ok True if `verify` succeeds.
    /// @return errorCode A `Reason` value; `Reason.REVERTED` for a revert that is not a `Rejected` error.
    /// @return callIndex Index of the failing call, or `NO_INDEX`.
    function check(
        PackedUserOperation calldata op,
        bytes32 userOpHash,
        Authorization calldata auth,
        Intent calldata intent
    ) external view returns (bool ok, uint8 errorCode, uint256 callIndex) {
        // slither-disable-next-line unused-return (only success or the revert reason matters)
        try this.verify(op, userOpHash, auth, intent) {
            return (true, uint8(Reason.NONE), NO_INDEX);
        } catch (bytes memory err) {
            if (err.length == 68 && bytes4(err) == Rejected.selector) {
                (uint256 reason, uint256 idx) = abi.decode(CallLib.slice(err, 4, 68), (uint256, uint256));
                return (false, uint8(reason), idx);
            }
            return (false, uint8(Reason.REVERTED), NO_INDEX);
        }
    }

    // ───────────────────────────── envelope (§3.1) ─────────────────────────────

    function _checkEnvelope(
        PackedUserOperation calldata op,
        bytes32 userOpHash,
        Authorization calldata auth,
        Intent calldata intent,
        IAllowlistRegistry reg,
        Config memory cfg
    ) private view returns (bytes32 h) {
        h = UserOpLib.hash(op, ENTRY_POINT);
        if (h != userOpHash) reject(Reason.HASH_MISMATCH, NO_INDEX);

        // The v0.7 hash does not commit to the 7702 delegate: this is the only protection against a bad one.
        if (auth.delegate != address(0)) {
            if (auth.delegate != MAV2_7702_IMPL) reject(Reason.BAD_DELEGATE, NO_INDEX);
            if (auth.chainId != block.chainid) reject(Reason.BAD_AUTH_CHAIN_ID, NO_INDEX);
        }
        bytes memory code = op.sender.code;
        if (code.length != 0) {
            // Already delegated: must be to MAv2 (EXTCODECOPY returns the 0xef0100 ‖ delegate designator).
            if (keccak256(code) != keccak256(abi.encodePacked(hex"ef0100", MAV2_7702_IMPL))) {
                reject(Reason.BAD_ACCOUNT_CODE, NO_INDEX);
            }
        } else if (auth.delegate == address(0)) {
            reject(Reason.BAD_ACCOUNT_CODE, NO_INDEX); // plain EOA and no authorization: nothing to execute
        }

        if (op.sender != intent.user) reject(Reason.WRONG_SENDER, NO_INDEX);
        if (op.initCode.length != 0) reject(Reason.INIT_CODE_NOT_EMPTY, NO_INDEX);

        if (op.paymasterAndData.length != 0) {
            if (op.paymasterAndData.length < 52) reject(Reason.PAYMASTER_NOT_ALLOWED, NO_INDEX);
            address paymaster = address(bytes20(op.paymasterAndData[:20]));
            if (!reg.isAllowed(Category.PAYMASTER, paymaster)) reject(Reason.PAYMASTER_NOT_ALLOWED, NO_INDEX);
        } else {
            // The user pays gas: bound price and limits.
            uint256 totalGas =
                UserOpLib.high128(op.accountGasLimits) + UserOpLib.low128(op.accountGasLimits) + op.preVerificationGas;
            if (UserOpLib.low128(op.gasFees) > cfg.maxFeePerGas || totalGas > cfg.maxTotalGas) {
                reject(Reason.GAS_CAP_EXCEEDED, NO_INDEX);
            }
        }
    }

    /// @dev Call 0 must be `DeadlineGuard.requireBefore(d)` with `now < d <= now + maxBatchTtl`.
    function _checkDeadline(Call[] memory calls, Config memory cfg) private view returns (uint256 d) {
        if (
            calls.length == 0 || calls[0].target != DEADLINE_GUARD
                || CallLib.selectorOf(calls[0].data) != DeadlineGuard.requireBefore.selector
        ) reject(Reason.MISSING_DEADLINE, 0);
        if (calls[0].data.length != 36) reject(Reason.MALFORMED_CALL, 0);
        d = CallLib.word(calls[0].data, 0);
        if (d <= block.timestamp || d > block.timestamp + cfg.maxBatchTtl) reject(Reason.BAD_DEADLINE, 0);
    }

    // ───────────────────────────── actions (§3.2, §3.3) ─────────────────────────────

    function _checkActions(Call[] memory calls, Intent calldata intent, IAllowlistRegistry reg, Config memory cfg)
        private
        view
    {
        _checkIntentShape(intent);
        Layout memory l = BatchLayout.parse(calls, cfg.feeToken);
        Call memory main = calls[l.main];

        MainResult memory m;
        Action a = intent.action;
        if (a == Action.STAKE || a == Action.UNSTAKE) {
            m = _vault(main, l.main, intent, reg, cfg.feeToken);
        } else if (a == Action.BUY || a == Action.SELL) {
            m = SwapRules.check(main, l.main, intent, reg, cfg);
        } else {
            m = BridgeRules.check(main, l.main, intent, reg, cfg);
        }

        AllowanceRules.check(calls, l, m, intent.user, a != Action.UNSTAKE);
        if (l.fee != NO_INDEX) FeeRules.check(calls[l.fee], l.fee, intent.maxFee, m.notional, reg, cfg);
    }

    function _vault(Call memory c, uint256 idx, Intent calldata intent, IAllowlistRegistry reg, address feeToken)
        private
        view
        returns (MainResult memory)
    {
        if (c.target != intent.target) reject(Reason.TARGET_NOT_ALLOWED, idx);
        bool stake = intent.action == Action.STAKE;
        if (reg.isAllowed(Category.VAULT_4626, c.target)) {
            return stake
                ? Erc4626Rules.stake(c, idx, intent.user, intent.amount, feeToken)
                : Erc4626Rules.unstake(c, idx, intent.user, intent.amount, feeToken);
        }
        if (reg.isAllowed(Category.AAVE_POOL, c.target)) {
            return stake
                ? AaveRules.stake(c, idx, intent.user, intent.amount, feeToken)
                : AaveRules.unstake(c, idx, intent.user, intent.amount, feeToken);
        }
        reject(Reason.TARGET_NOT_ALLOWED, idx);
    }

    function _checkIntentShape(Intent calldata intent) private pure {
        if (intent.action == Action.BRIDGE) {
            if (intent.target != address(0) || intent.dstChainId == 0) reject(Reason.BAD_INTENT, NO_INDEX);
        } else if (intent.dstChainId != 0 || intent.recipient != bytes32(0)) {
            reject(Reason.BAD_INTENT, NO_INDEX);
        }
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    function _s() private pure returns (VerifierStorage storage s) {
        assembly {
            s.slot := STORAGE_LOCATION
        }
    }
}

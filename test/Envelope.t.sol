// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {DeadlineGuard} from "../src/DeadlineGuard.sol";
import {UserOpLib} from "../src/libraries/UserOpLib.sol";
import {Reason} from "../src/types/Errors.sol";
import {Action, Authorization, Call, Intent, PackedUserOperation} from "../src/types/Types.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

contract UserOpLibHarness {
    function hash(PackedUserOperation calldata op) external view returns (bytes32) {
        return UserOpLib.hash(op, 0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    }
}

contract EnvelopeTest is VerifierTestBase {
    uint256 internal constant AMOUNT = 1000e6;

    function _stakeCalls() internal view returns (Call[] memory) {
        return _calls(
            _deadlineCall(),
            _approve(address(usdc), address(vault), AMOUNT),
            Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user))),
            _fee(2.1e6)
        );
    }

    function _stakeIntent() internal view returns (Intent memory it) {
        it = _intent(Action.STAKE, address(vault), AMOUNT);
        it.maxFee = 2.1e6;
    }

    function _reject(PackedUserOperation memory op, Authorization memory auth, Reason r, uint256 idx) internal {
        _expectReject(r, idx);
        this.verifyWith(op, _hash(op), auth, _stakeIntent());
    }

    function verifyWith(PackedUserOperation memory op, bytes32 h, Authorization memory auth, Intent memory it)
        external
        view
    {
        verifier.verify(op, h, auth, it);
    }

    // ───────────────────────── happy path ─────────────────────────

    function test_validStake_returnsHashAndDeadline() public view {
        PackedUserOperation memory op = _op(_stakeCalls());
        (bytes32 h, uint256 d) = _verify(op, _stakeIntent());
        assertEq(h, _hash(op));
        assertEq(d, block.timestamp + 300);
    }

    /// Pinned against EntryPoint v0.7 `getUserOpHash` on Base (chainid 8453), queried with cast.
    function test_userOpHash_matchesEntryPointV07() public {
        vm.chainId(8453);
        PackedUserOperation memory op;
        op.sender = 0x1111111111111111111111111111111111111111;
        op.nonce = 5;
        op.callData = hex"34fcd5be";
        op.accountGasLimits = bytes32((uint256(1) << 128) | 2);
        op.preVerificationGas = 3;
        op.gasFees = bytes32((uint256(4) << 128) | 5);
        assertEq(new UserOpLibHarness().hash(op), 0xec0bf5ac77b0bf6963646b4f99c86205f7cef9ebb3bc5d2980848b5cf1e14835);
    }

    function test_check_ok() public view {
        PackedUserOperation memory op = _op(_stakeCalls());
        (bool ok, uint8 code, uint256 idx) = verifier.check(op, _hash(op), _noAuth(), _stakeIntent());
        assertTrue(ok);
        assertEq(code, 0);
        assertEq(idx, _noIndex());
    }

    function test_check_returnsReasonAndIndex() public view {
        Call[] memory calls = _stakeCalls();
        calls[1] = _approve(address(usdc), address(vault), type(uint256).max);
        PackedUserOperation memory op = _op(calls);
        (bool ok, uint8 code, uint256 idx) = verifier.check(op, _hash(op), _noAuth(), _stakeIntent());
        assertFalse(ok);
        assertEq(code, uint8(Reason.BAD_APPROVE));
        assertEq(idx, 1);
    }

    function test_check_undecodableIsReverted() public view {
        PackedUserOperation memory op = _opRaw(abi.encodePacked(bytes4(0x34fcd5be), uint256(0x20), uint256(1)));
        (bool ok, uint8 code,) = verifier.check(op, _hash(op), _noAuth(), _stakeIntent());
        assertFalse(ok);
        assertEq(code, uint8(Reason.REVERTED));
    }

    // ───────────────────────── hash / 7702 ─────────────────────────

    function test_hashMismatch() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        _expectReject(Reason.HASH_MISMATCH, _noIndex());
        this.verifyWith(op, bytes32(uint256(_hash(op)) ^ 1), _noAuth(), _stakeIntent());
    }

    function test_hashDependsOnChainId() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        bytes32 h = _hash(op);
        vm.chainId(8453);
        _expectReject(Reason.HASH_MISMATCH, _noIndex());
        this.verifyWith(op, h, _noAuth(), _stakeIntent());
    }

    function test_newAuthorization_toMav2_ok() public {
        vm.etch(user, "");
        PackedUserOperation memory op = _op(_stakeCalls());
        verifier.verify(op, _hash(op), Authorization(block.chainid, MAV2, 0), _stakeIntent());
    }

    function test_wrongDelegate() public {
        vm.etch(user, "");
        _reject(_op(_stakeCalls()), Authorization(block.chainid, attacker, 0), Reason.BAD_DELEGATE, _noIndex());
    }

    function test_authChainIdZero() public {
        vm.etch(user, "");
        _reject(_op(_stakeCalls()), Authorization(0, MAV2, 0), Reason.BAD_AUTH_CHAIN_ID, _noIndex());
    }

    function test_authOtherChain() public {
        vm.etch(user, "");
        _reject(_op(_stakeCalls()), Authorization(8453, MAV2, 0), Reason.BAD_AUTH_CHAIN_ID, _noIndex());
    }

    function test_alreadyDelegatedElsewhere() public {
        vm.etch(user, abi.encodePacked(hex"ef0100", attacker));
        _reject(_op(_stakeCalls()), _noAuth(), Reason.BAD_ACCOUNT_CODE, _noIndex());
    }

    function test_alreadyDelegatedElsewhere_evenWithNewAuth() public {
        vm.etch(user, abi.encodePacked(hex"ef0100", attacker));
        _reject(_op(_stakeCalls()), Authorization(block.chainid, MAV2, 0), Reason.BAD_ACCOUNT_CODE, _noIndex());
    }

    function test_senderIsContract() public {
        vm.etch(user, hex"6080");
        _reject(_op(_stakeCalls()), _noAuth(), Reason.BAD_ACCOUNT_CODE, _noIndex());
    }

    function test_plainEoaWithoutAuth() public {
        vm.etch(user, "");
        _reject(_op(_stakeCalls()), _noAuth(), Reason.BAD_ACCOUNT_CODE, _noIndex());
    }

    function test_wrongSender() public {
        address other = makeAddr("other");
        _delegate(other);
        PackedUserOperation memory op = _op(_stakeCalls());
        op.sender = other;
        _reject(op, _noAuth(), Reason.WRONG_SENDER, _noIndex());
    }

    function test_initCodeNotEmpty() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.initCode = abi.encodePacked(bytes20(uint160(0x7702)));
        _reject(op, _noAuth(), Reason.INIT_CODE_NOT_EMPTY, _noIndex());
    }

    // ───────────────────────── gas / paymaster ─────────────────────────

    function test_unlistedPaymaster() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.paymasterAndData = abi.encodePacked(attacker, uint128(1), uint128(1));
        _reject(op, _noAuth(), Reason.PAYMASTER_NOT_ALLOWED, _noIndex());
    }

    function test_shortPaymasterData() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.paymasterAndData = abi.encodePacked(paymaster);
        _reject(op, _noAuth(), Reason.PAYMASTER_NOT_ALLOWED, _noIndex());
    }

    function test_noPaymaster_withinCaps_ok() public view {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.paymasterAndData = "";
        _verify(op, _stakeIntent());
    }

    function test_noPaymaster_feePerGasAboveCap() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.paymasterAndData = "";
        op.gasFees = bytes32((uint256(1 gwei) << 128) | 51 gwei);
        _reject(op, _noAuth(), Reason.GAS_CAP_EXCEEDED, _noIndex());
    }

    function test_noPaymaster_gasLimitsAboveCap() public {
        PackedUserOperation memory op = _op(_stakeCalls());
        op.paymasterAndData = "";
        op.accountGasLimits = bytes32((uint256(1_000_000) << 128) | 1_000_000);
        _reject(op, _noAuth(), Reason.GAS_CAP_EXCEEDED, _noIndex());
    }

    // ───────────────────────── account entry point ─────────────────────────

    function test_plainExecuteRejected() public {
        bytes memory cd = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", address(vault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user))
        );
        _reject(_opRaw(cd), _noAuth(), Reason.BAD_CALLDATA, _noIndex());
    }

    function test_executeUserOpPrefixRejected() public {
        bytes memory inner = _op(_stakeCalls()).callData;
        bytes memory cd = abi.encodePacked(bytes4(0x8dd7712f), inner);
        _reject(_opRaw(cd), _noAuth(), Reason.BAD_CALLDATA, _noIndex());
    }

    function test_performCreateRejected() public {
        bytes memory cd = abi.encodeWithSignature("performCreate(uint256,bytes)", 0, hex"00");
        _reject(_opRaw(cd), _noAuth(), Reason.BAD_CALLDATA, _noIndex());
    }

    function test_trailingCalldataRejected() public {
        bytes memory cd = abi.encodePacked(_op(_stakeCalls()).callData, uint256(0));
        _reject(_opRaw(cd), _noAuth(), Reason.BAD_CALLDATA, _noIndex());
    }

    function test_selfCall_installValidation() public {
        Call[] memory calls = _stakeCalls();
        calls[1] = Call(user, 0, abi.encodeWithSignature("installValidation(bytes25,bytes4[],bytes,bytes[])"));
        _reject(_op(calls), _noAuth(), Reason.SELF_CALL_FORBIDDEN, 1);
    }

    function test_selfCall_upgradeToAndCall() public {
        Call[] memory calls = _stakeCalls();
        calls[3] = Call(user, 0, abi.encodeWithSignature("upgradeToAndCall(address,bytes)", attacker, ""));
        _reject(_op(calls), _noAuth(), Reason.SELF_CALL_FORBIDDEN, 3);
    }

    function test_nativeValue() public {
        Call[] memory calls = _stakeCalls();
        calls[2].value = 1;
        _reject(_op(calls), _noAuth(), Reason.NATIVE_VALUE, 2);
    }

    // ───────────────────────── deadline ─────────────────────────

    function test_missingDeadline() public {
        Call[] memory calls = _calls(
            _approve(address(usdc), address(vault), AMOUNT),
            Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user)))
        );
        _reject(_op(calls), _noAuth(), Reason.MISSING_DEADLINE, 0);
    }

    function test_deadlineNotFirst() public {
        Call[] memory calls = _calls(
            _approve(address(usdc), address(vault), AMOUNT),
            _deadlineCall(),
            Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user)))
        );
        _reject(_op(calls), _noAuth(), Reason.MISSING_DEADLINE, 0);
    }

    function test_deadlineExpired() public {
        Call[] memory calls = _stakeCalls();
        calls[0] = _deadlineCall(block.timestamp);
        _reject(_op(calls), _noAuth(), Reason.BAD_DEADLINE, 0);
    }

    function test_deadlineBeyondTtl() public {
        Call[] memory calls = _stakeCalls();
        calls[0] = _deadlineCall(block.timestamp + 601);
        _reject(_op(calls), _noAuth(), Reason.BAD_DEADLINE, 0);
    }

    function test_deadlineAtTtl_ok() public view {
        Call[] memory calls = _stakeCalls();
        calls[0] = _deadlineCall(block.timestamp + 600);
        _verify(calls, _stakeIntent());
    }

    function test_deadlineTrailingBytes() public {
        Call[] memory calls = _stakeCalls();
        calls[0].data = abi.encodePacked(calls[0].data, uint8(0));
        _reject(_op(calls), _noAuth(), Reason.MALFORMED_CALL, 0);
    }

    function test_deadlineGuard_reverts_afterDeadline() public {
        guard.requireBefore(block.timestamp);
        vm.expectRevert(DeadlineGuard.Expired.selector);
        guard.requireBefore(block.timestamp - 1);
    }

    // ───────────────────────── registry state ─────────────────────────

    function test_paused() public {
        vm.prank(guardian);
        registry.pause();
        _reject(_op(_stakeCalls()), _noAuth(), Reason.PAUSED, _noIndex());
    }

    function test_extraCallRejected() public {
        Call[] memory calls = _calls(
            _deadlineCall(),
            _approve(address(usdc), address(vault), AMOUNT),
            Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user))),
            Call(address(usdc), 0, abi.encodeCall(IERC20.transfer, (attacker, 1))),
            _fee(1e6)
        );
        _reject(_op(calls), _noAuth(), Reason.UNEXPECTED_CALL, 3);
    }

    function test_badIntentShape() public {
        Intent memory it = _stakeIntent();
        it.dstChainId = 56;
        PackedUserOperation memory op = _op(_stakeCalls());
        _expectReject(Reason.BAD_INTENT, _noIndex());
        this.verifyWith(op, _hash(op), _noAuth(), it);
    }
}

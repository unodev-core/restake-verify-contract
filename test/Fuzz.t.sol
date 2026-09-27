// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {IModularAccountV2} from "../src/interfaces/IExternal.sol";
import {Reason} from "../src/types/Errors.sol";
import {Action, Call, Intent, PackedUserOperation} from "../src/types/Types.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

/// Fuzzed malicious mutations of a valid STAKE batch.
contract FuzzTest is VerifierTestBase {
    uint256 internal constant AMOUNT = 1000e6;

    function _intentFor(uint256 amount) internal view returns (Intent memory it) {
        it = _intent(Action.STAKE, address(vault), amount);
        it.maxFee = 10e6;
    }

    function _batch(uint256 amount, uint256 approveAmt, address receiver, uint256 fee)
        internal
        view
        returns (Call[] memory)
    {
        return _calls(
            _deadlineCall(),
            _approve(address(usdc), address(vault), approveAmt),
            Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (amount, receiver))),
            _fee(fee)
        );
    }

    function _check(Call[] memory calls, Intent memory it) internal view returns (bool ok, uint8 code, uint256 idx) {
        PackedUserOperation memory op = _op(calls);
        return verifier.check(op, _hash(op), _noAuth(), it);
    }

    function testFuzz_receiverMustBeUser(address receiver) public view {
        vm.assume(receiver != user);
        (bool ok, uint8 code, uint256 idx) = _check(_batch(AMOUNT, AMOUNT, receiver, 1e6), _intentFor(AMOUNT));
        assertFalse(ok);
        assertEq(code, uint8(Reason.BAD_RECEIVER));
        assertEq(idx, 2);
    }

    function testFuzz_approveMustEqualAmount(uint256 approveAmt) public view {
        vm.assume(approveAmt != AMOUNT);
        (bool ok, uint8 code,) = _check(_batch(AMOUNT, approveAmt, user, 1e6), _intentFor(AMOUNT));
        assertFalse(ok);
        assertEq(code, uint8(Reason.BAD_APPROVE));
    }

    function testFuzz_feeBounded(uint256 amount, uint256 fee) public view {
        amount = bound(amount, 1, 1e15);
        (bool ok,,) = _check(_batch(amount, amount, user, fee), _intentFor(amount));
        uint256 cap = FLAT_FEE + amount * 50 / 10_000;
        assertEq(ok, fee <= 10e6 && fee <= cap);
    }

    function testFuzz_deadlineWindow(uint256 d) public view {
        Call[] memory calls = _batch(AMOUNT, AMOUNT, user, 1e6);
        calls[0] = _deadlineCall(d);
        (bool ok,,) = _check(calls, _intentFor(AMOUNT));
        assertEq(ok, d > block.timestamp && d <= block.timestamp + 600);
    }

    /// Any single-byte corruption of callData either breaks verification or leaves an op that still passes every
    /// rule; it must never make `check` itself revert.
    function testFuzz_byteFlip_neverRevertsCheck(uint256 pos, uint8 xorMask) public view {
        vm.assume(xorMask != 0);
        PackedUserOperation memory op = _op(_batch(AMOUNT, AMOUNT, user, 1e6));
        pos = bound(pos, 0, op.callData.length - 1);
        op.callData[pos] = bytes1(uint8(op.callData[pos]) ^ xorMask);
        verifier.check(op, _hash(op), _noAuth(), _intentFor(AMOUNT));
    }

    /// An extra call to any target, inserted at any position after the deadline, is always rejected.
    function testFuzz_extraCallRejected(address target, bytes calldata data, uint256 pos) public view {
        vm.assume(target != user);
        Call[] memory base = _batch(AMOUNT, AMOUNT, user, 1e6);
        pos = bound(pos, 1, base.length);
        Call[] memory calls = new Call[](base.length + 1);
        for (uint256 i; i < calls.length; ++i) {
            if (i < pos) calls[i] = base[i];
            else if (i == pos) calls[i] = Call(target, 0, data);
            else calls[i] = base[i - 1];
        }
        (bool ok,,) = _check(calls, _intentFor(AMOUNT));
        assertFalse(ok);
    }

    function testFuzz_randomCallData_neverPasses(bytes calldata data) public view {
        PackedUserOperation memory op = _opRaw(abi.encodePacked(IModularAccountV2.executeBatch.selector, data));
        (bool ok,,) = verifier.check(op, _hash(op), _noAuth(), _intentFor(AMOUNT));
        assertFalse(ok);
    }
}

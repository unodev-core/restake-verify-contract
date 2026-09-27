// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAcrossSpokePool} from "../src/interfaces/IExternal.sol";
import {Reason} from "../src/types/Errors.sol";
import {Action, BridgeConfig, Call, Category, Intent} from "../src/types/Types.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

/// BRIDGE through Across (USDC 6 dec here -> Binance-Peg USDC 18 dec on chain 56).
contract BridgeTest is VerifierTestBase {
    uint256 internal constant IN = 100e6;
    uint256 internal constant OUT = 99.8e18;
    uint256 internal constant MIN_OUT = 99.5e18;
    uint256 internal constant FEE = 0.1e6;

    struct Dep {
        bytes32 depositor;
        bytes32 recipient;
        bytes32 inputToken;
        bytes32 outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 dstChainId;
        bytes32 exclusiveRelayer;
        uint32 quoteTimestamp;
        uint32 fillDeadline;
        uint32 exclusivity;
        bytes message;
    }

    function _b(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _dep() internal view returns (Dep memory d) {
        d = Dep({
            depositor: _b(user),
            recipient: _b(user),
            inputToken: _b(address(usdc)),
            outputToken: bscUsdc,
            inputAmount: IN,
            outputAmount: OUT,
            dstChainId: DST_CHAIN,
            exclusiveRelayer: bytes32(0),
            quoteTimestamp: uint32(block.timestamp - 30),
            fillDeadline: uint32(block.timestamp + 2 hours),
            exclusivity: 0,
            message: ""
        });
    }

    function _encode(Dep memory d) internal pure returns (bytes memory) {
        return abi.encodeCall(
            IAcrossSpokePool.deposit,
            (
                d.depositor,
                d.recipient,
                d.inputToken,
                d.outputToken,
                d.inputAmount,
                d.outputAmount,
                d.dstChainId,
                d.exclusiveRelayer,
                d.quoteTimestamp,
                d.fillDeadline,
                d.exclusivity,
                d.message
            )
        );
    }

    function _depositCall(Dep memory d) internal view returns (Call memory) {
        return Call(spokePool, 0, abi.encodePacked(_encode(d), ACROSS_SUFFIX));
    }

    function _batch(Call memory dep) internal view returns (Call[] memory) {
        return _calls(_deadlineCall(), _approve(address(usdc), spokePool, IN), dep, _fee(FEE));
    }

    function _bridgeIntent() internal view returns (Intent memory it) {
        it = _intent(Action.BRIDGE, address(0), IN);
        it.payToken = address(usdc);
        it.minOut = MIN_OUT;
        it.maxFee = FEE;
        it.dstChainId = DST_CHAIN;
        it.recipient = _b(user);
    }

    function _rejectDep(Dep memory d, Reason r) internal {
        _assertRejected(_batch(_depositCall(d)), _bridgeIntent(), r, 2);
    }

    // ───────────────────────── happy paths ─────────────────────────

    function test_bridge_ok() public view {
        _verify(_batch(_depositCall(_dep())), _bridgeIntent());
    }

    function test_bridge_withoutSuffix_ok() public view {
        _verify(_batch(Call(spokePool, 0, _encode(_dep()))), _bridgeIntent());
    }

    function test_bridge_depositV3_ok() public view {
        Dep memory d = _dep();
        bytes memory data = abi.encodeCall(
            IAcrossSpokePool.depositV3,
            (
                user,
                user,
                address(usdc),
                address(uint160(uint256(bscUsdc))),
                IN,
                OUT,
                DST_CHAIN,
                address(0),
                d.quoteTimestamp,
                d.fillDeadline,
                0,
                ""
            )
        );
        _verify(_batch(Call(spokePool, 0, abi.encodePacked(data, ACROSS_SUFFIX))), _bridgeIntent());
    }

    // ───────────────────────── recipient / refund ─────────────────────────

    function test_bridge_recipientAttacker() public {
        Dep memory d = _dep();
        d.recipient = _b(attacker);
        _rejectDep(d, Reason.BAD_RECEIVER);
    }

    function test_bridge_intentRecipientNotUser() public {
        Dep memory d = _dep();
        d.recipient = _b(attacker);
        Intent memory it = _bridgeIntent();
        it.recipient = _b(attacker);
        _assertRejected(_batch(_depositCall(d)), it, Reason.BAD_RECEIVER, 2);
    }

    function test_bridge_depositorAttacker() public {
        Dep memory d = _dep();
        d.depositor = _b(attacker);
        _rejectDep(d, Reason.BAD_RECEIVER);
    }

    function test_bridge_dirtyDepositor() public {
        Dep memory d = _dep();
        d.depositor = bytes32(uint256(d.depositor) | (uint256(1) << 200));
        _rejectDep(d, Reason.MALFORMED_CALL);
    }

    // ───────────────────────── route / amounts ─────────────────────────

    function test_bridge_wrongOutputToken() public {
        Dep memory d = _dep();
        d.outputToken = _b(attacker);
        _rejectDep(d, Reason.BAD_ROUTE);
    }

    function test_bridge_unlistedRoute() public {
        Dep memory d = _dep();
        d.dstChainId = 10;
        Intent memory it = _bridgeIntent();
        it.dstChainId = 10;
        _assertRejected(_batch(_depositCall(d)), it, Reason.BAD_ROUTE, 2);
    }

    function test_bridge_dstChainDiffersFromIntent() public {
        Dep memory d = _dep();
        d.dstChainId = 10;
        _rejectDep(d, Reason.BAD_ROUTE);
    }

    function test_bridge_dstIsThisChain() public {
        Dep memory d = _dep();
        d.dstChainId = block.chainid;
        Intent memory it = _bridgeIntent();
        it.dstChainId = block.chainid;
        _assertRejected(_batch(_depositCall(d)), it, Reason.BAD_ROUTE, 2);
    }

    function test_bridge_outputBelowIntent() public {
        Dep memory d = _dep();
        d.outputAmount = MIN_OUT - 1;
        _rejectDep(d, Reason.OUTPUT_TOO_LOW);
    }

    function test_bridge_decimalsMixup_caughtByBackstop() public {
        // A careless partner passes minOut in source decimals; the deposit pays out 99.8 "wei-USDC".
        Dep memory d = _dep();
        d.outputAmount = 99.8e6;
        Intent memory it = _bridgeIntent();
        it.minOut = 99e6;
        _assertRejected(_batch(_depositCall(d)), it, Reason.OUTPUT_TOO_LOW, 2);
    }

    function test_bridge_providerFeeAboveCap() public {
        Dep memory d = _dep();
        d.outputAmount = 99.5e18 - 1; // > 50 bps below the rescaled input
        Intent memory it = _bridgeIntent();
        it.minOut = 1;
        _assertRejected(_batch(_depositCall(d)), it, Reason.OUTPUT_TOO_LOW, 2);
    }

    function test_bridge_inputAmountDiffers() public {
        Dep memory d = _dep();
        d.inputAmount = IN - 1;
        _rejectDep(d, Reason.BAD_AMOUNT);
    }

    function test_bridge_wrongInputToken() public {
        Dep memory d = _dep();
        d.inputToken = _b(address(dai));
        _rejectDep(d, Reason.TARGET_NOT_ALLOWED);
    }

    // ───────────────────────── time bounds ─────────────────────────

    function test_bridge_fillDeadlineTooFar() public {
        Dep memory d = _dep();
        d.fillDeadline = uint32(block.timestamp + 4 hours + 1);
        _rejectDep(d, Reason.FILL_WINDOW_TOO_LONG);
    }

    function test_bridge_staleQuote() public {
        Dep memory d = _dep();
        d.quoteTimestamp = uint32(block.timestamp - 301);
        _rejectDep(d, Reason.STALE_QUOTE);
    }

    function test_bridge_futureQuote() public {
        Dep memory d = _dep();
        d.quoteTimestamp = uint32(block.timestamp + 1);
        _rejectDep(d, Reason.STALE_QUOTE);
    }

    // ───────────────────────── shape ─────────────────────────

    function test_bridge_nonEmptyMessage() public {
        Dep memory d = _dep();
        d.message = hex"01";
        _rejectDep(d, Reason.BAD_BRIDGE_DEPOSIT);
    }

    function test_bridge_wrongSuffix() public {
        Call memory c = Call(spokePool, 0, abi.encodePacked(_encode(_dep()), hex"1dc0de0360"));
        _assertRejected(_batch(c), _bridgeIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_bridge_extraAfterSuffix() public {
        Call memory c = Call(spokePool, 0, abi.encodePacked(_encode(_dep()), ACROSS_SUFFIX, hex"00"));
        _assertRejected(_batch(c), _bridgeIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_bridge_depositNowRejected() public {
        Dep memory d = _dep();
        bytes memory data = abi.encodeWithSignature(
            "depositNow(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,bytes32,uint32,uint32,bytes)",
            d.depositor,
            d.recipient,
            d.inputToken,
            d.outputToken,
            d.inputAmount,
            d.outputAmount,
            d.dstChainId,
            d.exclusiveRelayer,
            uint32(7200),
            uint32(0),
            bytes("")
        );
        _assertRejected(_batch(Call(spokePool, 0, data)), _bridgeIntent(), Reason.BAD_SELECTOR, 2);
    }

    function test_bridge_unsafeDepositRejected() public {
        bytes memory data = abi.encodeWithSignature(
            "unsafeDeposit(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,bytes32,uint256,uint32,uint32,uint32,bytes)",
            _b(user),
            _b(user),
            _b(address(usdc)),
            bscUsdc,
            IN,
            OUT,
            DST_CHAIN,
            bytes32(0),
            uint256(1),
            uint32(block.timestamp),
            uint32(block.timestamp + 1 hours),
            uint32(0),
            bytes("")
        );
        _assertRejected(_batch(Call(spokePool, 0, data)), _bridgeIntent(), Reason.BAD_SELECTOR, 2);
    }

    function test_bridge_selectorDisabledInRow() public {
        // Replace the row with one that only enables `deposit`; depositV3 must then fail.
        BridgeConfig memory bc = _acrossConfig();
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = IAcrossSpokePool.deposit.selector;
        bc.selectors = sels;
        vm.prank(manager);
        bytes32 id = registry.scheduleBridge(spokePool, bc);
        vm.warp(block.timestamp + registry.DELAY());
        registry.execute(id);

        Dep memory d = _dep();
        bytes memory data = abi.encodeCall(
            IAcrossSpokePool.depositV3,
            (
                user,
                user,
                address(usdc),
                address(uint160(uint256(bscUsdc))),
                IN,
                OUT,
                DST_CHAIN,
                address(0),
                d.quoteTimestamp,
                d.fillDeadline,
                0,
                ""
            )
        );
        _assertRejected(_batch(Call(spokePool, 0, data)), _bridgeIntent(), Reason.BAD_SELECTOR, 2);
    }

    function test_bridge_nativeValue() public {
        Call memory c = _depositCall(_dep());
        c.value = 1 ether;
        _assertRejected(_batch(c), _bridgeIntent(), Reason.NATIVE_VALUE, 2);
    }

    function test_bridge_intentWithTarget() public {
        Intent memory it = _bridgeIntent();
        it.target = spokePool;
        _expectReject(Reason.BAD_INTENT, _noIndex());
        this.externalVerify(_op(_batch(_depositCall(_dep()))), it);
    }

    function test_bridge_removedBridgeFailsAndDropsRoutes() public {
        vm.prank(guardian);
        registry.remove(Category.BRIDGE, spokePool);
        assertEq(registry.listRoutes().length, 0);
        _assertRejected(_batch(_depositCall(_dep())), _bridgeIntent(), Reason.TARGET_NOT_ALLOWED, 2);
    }

    function test_bridge_approveToWrongSpender() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), attacker, IN), _depositCall(_dep()), _fee(FEE)),
            _bridgeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }
}

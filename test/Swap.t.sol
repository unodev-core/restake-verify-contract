// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAggregationRouterV6} from "../src/interfaces/IExternal.sol";
import {Reason} from "../src/types/Errors.sol";
import {Action, Call, Category, Intent, PoolType} from "../src/types/Types.sol";
import {MockPool} from "./utils/Mocks.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

/// BUY / SELL through the 1inch v6 router: generic `swap` and the `unoswap*` family.
contract SwapTest is VerifierTestBase {
    uint256 internal constant PAY = 100e6;
    uint256 internal constant STOCK_OUT = 0.5e18;
    uint256 internal constant FEE = 0.4e6;

    address internal executor = makeAddr("executor");

    uint256 internal constant V2 = 0;
    uint256 internal constant V3 = 1;
    uint256 internal constant CURVE = 2;

    function _buyIntent() internal view returns (Intent memory it) {
        it = _intent(Action.BUY, address(stock), PAY);
        it.payToken = address(usdc);
        it.minOut = STOCK_OUT;
        it.maxFee = FEE;
    }

    function _sellIntent() internal view returns (Intent memory it) {
        it = _intent(Action.SELL, address(stock), STOCK_OUT);
        it.payToken = address(usdc);
        it.minOut = PAY;
        it.maxFee = FEE;
    }

    function _desc(address src, address dst, uint256 amount, uint256 minReturn, address receiver)
        internal
        view
        returns (IAggregationRouterV6.SwapDescription memory)
    {
        return IAggregationRouterV6.SwapDescription({
            srcToken: src,
            dstToken: dst,
            srcReceiver: executor,
            dstReceiver: receiver,
            amount: amount,
            minReturnAmount: minReturn,
            flags: 0
        });
    }

    function _swapCall(IAggregationRouterV6.SwapDescription memory d) internal view returns (Call memory) {
        return Call(router, 0, abi.encodeCall(IAggregationRouterV6.swap, (executor, d, hex"deadbeef")));
    }

    function _buySwap() internal view returns (Call memory) {
        return _swapCall(_desc(address(usdc), address(stock), PAY, STOCK_OUT, user));
    }

    function _buy(Call memory swapCall) internal view returns (Call[] memory) {
        return _calls(_deadlineCall(), _approve(address(usdc), router, PAY), swapCall, _fee(FEE));
    }

    /// dex word: protocol ‖ zeroForOne ‖ pool, with zeroForOne derived from `tokenIn`.
    function _dex(address pool, uint256 protocol, address tokenIn) internal view returns (uint256) {
        bool zeroForOne = MockPool(pool).token0() == tokenIn;
        return (protocol << 253) | (zeroForOne ? uint256(1) << 247 : 0) | uint160(pool);
    }

    function _unoswap2(uint256 dex1, uint256 dex2) internal view returns (Call memory) {
        return Call(
            router,
            0,
            abi.encodeCall(IAggregationRouterV6.unoswap2, (uint160(address(usdc)), PAY, STOCK_OUT, dex1, dex2))
        );
    }

    function _usdcToStockRoute() internal view returns (uint256 d1, uint256 d2) {
        d1 = _dex(address(poolUsdcWbnb), V3, address(usdc));
        d2 = _dex(address(poolWbnbStock), V2, address(wbnb));
    }

    // ───────────────────────── generic swap ─────────────────────────

    function test_buy_swap_ok() public view {
        _verify(_buy(_buySwap()), _buyIntent());
    }

    function test_sell_swap_ok() public view {
        Call memory s = _swapCall(_desc(address(stock), address(usdc), STOCK_OUT, PAY, user));
        _verify(_calls(_deadlineCall(), _approve(address(stock), router, STOCK_OUT), s, _fee(FEE)), _sellIntent());
    }

    function test_sell_feeCapUsesMinOut() public {
        Intent memory it = _sellIntent();
        it.maxFee = 100e6;
        uint256 cap = FLAT_FEE + PAY * 50 / 10_000;
        Call memory s = _swapCall(_desc(address(stock), address(usdc), STOCK_OUT, PAY, user));
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(stock), router, STOCK_OUT), s, _fee(cap + 1)),
            it,
            Reason.FEE_TOO_HIGH,
            3
        );
    }

    function test_swap_dstReceiverAttacker() public {
        _assertRejected(
            _buy(_swapCall(_desc(address(usdc), address(stock), PAY, STOCK_OUT, attacker))),
            _buyIntent(),
            Reason.BAD_RECEIVER,
            2
        );
    }

    function test_swap_dstReceiverZero() public {
        _assertRejected(
            _buy(_swapCall(_desc(address(usdc), address(stock), PAY, STOCK_OUT, address(0)))),
            _buyIntent(),
            Reason.BAD_RECEIVER,
            2
        );
    }

    function test_swap_wrongDstToken() public {
        _assertRejected(
            _buy(_swapCall(_desc(address(usdc), address(wbnb), PAY, STOCK_OUT, user))), _buyIntent(), Reason.BAD_SWAP, 2
        );
    }

    function test_swap_minReturnBelowIntent() public {
        _assertRejected(
            _buy(_swapCall(_desc(address(usdc), address(stock), PAY, STOCK_OUT - 1, user))),
            _buyIntent(),
            Reason.MIN_OUT_TOO_LOW,
            2
        );
    }

    function test_swap_zeroMinOutIntent() public {
        Intent memory it = _buyIntent();
        it.minOut = 0;
        _assertRejected(_buy(_buySwap()), it, Reason.MIN_OUT_TOO_LOW, 2);
    }

    function test_swap_amountDiffers() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), router, PAY),
                _swapCall(_desc(address(usdc), address(stock), PAY - 1, STOCK_OUT, user))
            ),
            _buyIntent(),
            Reason.BAD_AMOUNT,
            2
        );
    }

    function test_swap_partialFill() public {
        IAggregationRouterV6.SwapDescription memory d = _desc(address(usdc), address(stock), PAY, STOCK_OUT, user);
        d.flags = 1;
        _assertRejected(_buy(_swapCall(d)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_swap_permit2Flag() public {
        IAggregationRouterV6.SwapDescription memory d = _desc(address(usdc), address(stock), PAY, STOCK_OUT, user);
        d.flags = 4;
        _assertRejected(_buy(_swapCall(d)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_swap_unlistedRouter() public {
        Call memory s = _buySwap();
        s.target = attacker;
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), attacker, PAY), s),
            _buyIntent(),
            Reason.TARGET_NOT_ALLOWED,
            2
        );
    }

    function test_swap_unlistedOndoToken() public {
        Intent memory it = _buyIntent();
        it.target = address(wbnb);
        _assertRejected(_buy(_buySwap()), it, Reason.TARGET_NOT_ALLOWED, 2);
    }

    function test_swap_trailingBytes() public {
        Call memory s = _buySwap();
        s.data = abi.encodePacked(s.data, uint256(0));
        _assertRejected(_buy(s), _buyIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_swap_standingAllowanceNoRevoke() public {
        vm.prank(user);
        usdc.approve(router, type(uint256).max);
        _assertRejected(_calls(_deadlineCall(), _buySwap(), _fee(FEE)), _buyIntent(), Reason.RESIDUAL_ALLOWANCE, 1);
        _verify(_calls(_deadlineCall(), _buySwap(), _approve(address(usdc), router, 0), _fee(FEE)), _buyIntent());
    }

    function test_swap_otherRouterMethodsRejected() public {
        bytes[] memory datas = new bytes[](3);
        datas[0] = abi.encodeWithSignature("ethUnoswap(uint256,uint256)", STOCK_OUT, uint256(1));
        datas[1] = abi.encodeWithSignature(
            "clipperSwap(address,uint256,address,address,uint256,uint256,uint256,bytes32,bytes32)",
            executor,
            uint256(uint160(address(usdc))),
            address(stock),
            PAY,
            STOCK_OUT,
            uint256(0),
            bytes32(0),
            bytes32(0)
        );
        datas[2] = abi.encodeWithSignature("fillOrder()");
        for (uint256 i; i < datas.length; ++i) {
            _assertRejected(_buy(Call(router, 0, datas[i])), _buyIntent(), Reason.BAD_SELECTOR, 2);
        }
    }

    // ───────────────────────── unoswap ─────────────────────────

    function test_unoswap2_twoHops_ok() public view {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _verify(_buy(_unoswap2(d1, d2)), _buyIntent());
    }

    function test_unoswapTo2_toUser_ok() public view {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        Call memory c = Call(
            router,
            0,
            abi.encodeCall(
                IAggregationRouterV6.unoswapTo2, (uint160(user), uint160(address(usdc)), PAY, STOCK_OUT, d1, d2)
            )
        );
        _verify(_buy(c), _buyIntent());
    }

    function test_unoswapTo_toAttacker() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        Call memory c = Call(
            router,
            0,
            abi.encodeCall(
                IAggregationRouterV6.unoswapTo2, (uint160(attacker), uint160(address(usdc)), PAY, STOCK_OUT, d1, d2)
            )
        );
        _assertRejected(_buy(c), _buyIntent(), Reason.BAD_RECEIVER, 2);
    }

    function test_unoswapTo_dirtyToWord() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        uint256 dirtyTo = (uint256(1) << 200) | uint160(user);
        Call memory c = Call(
            router,
            0,
            abi.encodeCall(IAggregationRouterV6.unoswapTo2, (dirtyTo, uint160(address(usdc)), PAY, STOCK_OUT, d1, d2))
        );
        _assertRejected(_buy(c), _buyIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_unoswap_sell_ok() public view {
        uint256 d1 = _dex(address(poolWbnbStock), V2, address(stock));
        uint256 d2 = _dex(address(poolUsdcWbnb), V3, address(wbnb));
        Call memory c = Call(
            router, 0, abi.encodeCall(IAggregationRouterV6.unoswap2, (uint160(address(stock)), STOCK_OUT, PAY, d1, d2))
        );
        _verify(_calls(_deadlineCall(), _approve(address(stock), router, STOCK_OUT), c, _fee(FEE)), _sellIntent());
    }

    function test_unoswap_v2FeeNumeratorAllowed() public view {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        d2 |= uint256(997_000_000) << 160;
        _verify(_buy(_unoswap2(d1, d2)), _buyIntent());
    }

    function test_unoswap_unlistedPool() public {
        uint256 d1 = _dex(address(unlistedPool), V3, address(usdc));
        Call memory c =
            Call(router, 0, abi.encodeCall(IAggregationRouterV6.unoswap, (uint160(address(usdc)), PAY, STOCK_OUT, d1)));
        _assertRejected(_buy(c), _buyIntent(), Reason.POOL_NOT_ALLOWED, 2);
    }

    function test_unoswap_protocolMismatch() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        d2 = (d2 & ~(uint256(7) << 253)) | (V3 << 253); // V2 pool labelled as V3
        _assertRejected(_buy(_unoswap2(d1, d2)), _buyIntent(), Reason.POOL_NOT_ALLOWED, 2);
    }

    function test_unoswap_flippedDirection() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        d1 ^= uint256(1) << 247;
        _assertRejected(_buy(_unoswap2(d1, d2)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_brokenHopChain() public {
        (uint256 d1,) = _usdcToStockRoute();
        // Second hop again starts from USDC, not from WBNB.
        _assertRejected(_buy(_unoswap2(d1, d1)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_endsInWrongToken() public {
        uint256 d1 = _dex(address(poolUsdcWbnb), V3, address(usdc));
        Call memory c =
            Call(router, 0, abi.encodeCall(IAggregationRouterV6.unoswap, (uint160(address(usdc)), PAY, STOCK_OUT, d1)));
        _assertRejected(_buy(c), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_unwrapFlag() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _assertRejected(_buy(_unoswap2(d1, d2 | (uint256(1) << 252))), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_notWrapFlag() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _assertRejected(_buy(_unoswap2(d1 | (uint256(1) << 251), d2)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_permit2Flag() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _assertRejected(_buy(_unoswap2(d1 | (uint256(1) << 250), d2)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_v3WithNumeratorBits() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _assertRejected(_buy(_unoswap2(d1 | (uint256(1) << 170), d2)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_curveHop() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        d1 = (d1 & ~(uint256(7) << 253)) | (CURVE << 253);
        _assertRejected(_buy(_unoswap2(d1, d2)), _buyIntent(), Reason.BAD_SWAP, 2);
    }

    function test_unoswap_dirtyTokenWord() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        uint256 dirtyToken = (uint256(1) << 255) | uint160(address(usdc));
        Call memory c =
            Call(router, 0, abi.encodeCall(IAggregationRouterV6.unoswap2, (dirtyToken, PAY, STOCK_OUT, d1, d2)));
        _assertRejected(_buy(c), _buyIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_unoswap_trailingBytes() public {
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        Call memory c = _unoswap2(d1, d2);
        c.data = abi.encodePacked(c.data, uint256(0));
        _assertRejected(_buy(c), _buyIntent(), Reason.MALFORMED_CALL, 2);
    }

    function test_unoswap_poolRemovedFailsImmediately() public {
        vm.prank(guardian);
        registry.remove(Category.SWAP_POOL, address(poolWbnbStock));
        assertEq(uint8(registry.poolType(address(poolWbnbStock))), uint8(PoolType.NONE));
        (uint256 d1, uint256 d2) = _usdcToStockRoute();
        _assertRejected(_buy(_unoswap2(d1, d2)), _buyIntent(), Reason.POOL_NOT_ALLOWED, 2);
    }
}

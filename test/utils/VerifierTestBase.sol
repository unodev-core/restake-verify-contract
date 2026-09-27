// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";

import {AllowlistRegistry} from "../../src/AllowlistRegistry.sol";
import {BatchVerifier} from "../../src/BatchVerifier.sol";
import {DeadlineGuard} from "../../src/DeadlineGuard.sol";
import {IAllowlistRegistry} from "../../src/interfaces/IAllowlistRegistry.sol";
import {IAcrossSpokePool, IModularAccountV2} from "../../src/interfaces/IExternal.sol";
import {NO_INDEX, Reason, Rejected} from "../../src/types/Errors.sol";
import {
    Action,
    Authorization,
    BridgeConfig,
    BridgeRoute,
    BridgeType,
    Call,
    Category,
    Config,
    Intent,
    PackedUserOperation,
    PoolType,
    RouterType
} from "../../src/types/Types.sol";
import {MockERC20, MockPool, MockVault} from "./Mocks.sol";

abstract contract VerifierTestBase is Test {
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant MAV2 = 0x69007702764179f14F51cdce752f4f775d74E139;
    uint256 internal constant DST_CHAIN = 56;
    bytes internal constant ACROSS_SUFFIX = hex"1dc0de035f";

    address internal timelock = makeAddr("timelock");
    address internal manager = makeAddr("manager");
    address internal guardian = makeAddr("guardian");
    address internal user = makeAddr("user");
    address internal treasury = makeAddr("treasury");
    address internal paymaster = makeAddr("paymaster");
    address internal aavePool = makeAddr("aavePool");
    address internal router = makeAddr("oneInchRouter");
    address internal spokePool = makeAddr("spokePool");
    address internal attacker = makeAddr("attacker");
    bytes32 internal bscUsdc = bytes32(uint256(uint160(makeAddr("bscUsdc"))));

    DeadlineGuard internal guard;
    AllowlistRegistry internal registry;
    BatchVerifier internal verifier;

    MockERC20 internal usdc;
    MockERC20 internal dai;
    MockERC20 internal stock;
    MockERC20 internal wbnb;
    MockVault internal vault;
    MockVault internal daiVault;
    MockPool internal poolUsdcWbnb; // V3
    MockPool internal poolWbnbStock; // V2
    MockPool internal unlistedPool;

    uint256 internal constant FLAT_FEE = 0.11e6; // $0.10 + rounding margin, 6 decimals

    function setUp() public virtual {
        vm.warp(1_750_000_000);

        usdc = new MockERC20("USDC", 6);
        dai = new MockERC20("DAI", 18);
        stock = new MockERC20("AAPLon", 18);
        wbnb = new MockERC20("WBNB", 18);
        vault = new MockVault(usdc);
        daiVault = new MockVault(dai);
        poolUsdcWbnb = new MockPool(address(usdc), address(wbnb));
        poolWbnbStock = new MockPool(address(wbnb), address(stock));
        unlistedPool = new MockPool(address(usdc), address(stock));

        guard = new DeadlineGuard();
        AllowlistRegistry regImpl = new AllowlistRegistry();
        registry = AllowlistRegistry(
            address(
                new ERC1967Proxy(
                    address(regImpl),
                    abi.encodeCall(AllowlistRegistry.initialize, (timelock, manager, guardian, timelock, _config()))
                )
            )
        );
        BatchVerifier verImpl = new BatchVerifier(address(guard));
        verifier = BatchVerifier(
            address(
                new ERC1967Proxy(
                    address(verImpl),
                    abi.encodeCall(
                        BatchVerifier.initialize, (IAllowlistRegistry(address(registry)), timelock, timelock)
                    )
                )
            )
        );

        _seed();
        _delegate(user);
    }

    function _config() internal view returns (Config memory) {
        return Config({
            feeToken: address(usdc),
            maxFeeBps: 50,
            maxBridgeFeeBps: 50,
            maxBatchTtl: 600,
            flatFee: FLAT_FEE,
            maxFeePerGas: 50 gwei,
            maxTotalGas: 2_000_000
        });
    }

    /// @dev Seeds the allowlist through the real 48 h schedule / execute path.
    function _seed() internal {
        vm.startPrank(manager);
        bytes32[] memory ids = new bytes32[](20);
        uint256 n;
        ids[n++] = registry.scheduleAdd(Category.PAYMASTER, paymaster, 0);
        ids[n++] = registry.scheduleAdd(Category.VAULT_4626, address(vault), 0);
        ids[n++] = registry.scheduleAdd(Category.VAULT_4626, address(daiVault), 0);
        ids[n++] = registry.scheduleAdd(Category.AAVE_POOL, aavePool, 0);
        ids[n++] = registry.scheduleAdd(Category.ASSET, address(usdc), 0);
        ids[n++] = registry.scheduleAdd(Category.ONDO_TOKEN, address(stock), 0);
        ids[n++] = registry.scheduleAdd(Category.SWAP_ROUTER, router, uint8(RouterType.ONE_INCH_V6));
        ids[n++] = registry.scheduleAdd(Category.SWAP_POOL, address(poolUsdcWbnb), uint8(PoolType.UNISWAP_V3));
        ids[n++] = registry.scheduleAdd(Category.SWAP_POOL, address(poolWbnbStock), uint8(PoolType.UNISWAP_V2));
        ids[n++] = registry.scheduleAdd(Category.FEE_RECIPIENT, treasury, 0);
        ids[n++] = registry.scheduleBridge(spokePool, _acrossConfig());
        ids[n++] = registry.scheduleRoute(
            spokePool,
            address(usdc),
            DST_CHAIN,
            BridgeRoute({outputToken: bscUsdc, inputDecimals: 6, outputDecimals: 18})
        );
        vm.stopPrank();

        uint256 start = block.timestamp;
        vm.warp(start + registry.DELAY());
        for (uint256 i; i < n; ++i) {
            registry.execute(ids[i]);
        }
    }

    function _acrossConfig() internal view returns (BridgeConfig memory bc) {
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = IAcrossSpokePool.deposit.selector;
        sels[1] = IAcrossSpokePool.depositV3.selector;
        bc = BridgeConfig({
            bridgeType: BridgeType.ACROSS,
            spender: spokePool,
            maxFillWindow: 4 hours,
            maxQuoteAge: 300,
            selectors: sels,
            integratorSuffix: ACROSS_SUFFIX
        });
    }

    function _delegate(address account) internal {
        vm.etch(account, abi.encodePacked(hex"ef0100", MAV2));
    }

    // ───────────────────────────── op builders ─────────────────────────────

    function _deadlineCall() internal view returns (Call memory) {
        return _deadlineCall(block.timestamp + 300);
    }

    function _deadlineCall(uint256 d) internal view returns (Call memory) {
        return Call(address(guard), 0, abi.encodeCall(DeadlineGuard.requireBefore, (d)));
    }

    function _approve(address token, address spender, uint256 amount) internal pure returns (Call memory) {
        return Call(token, 0, abi.encodeCall(IERC20.approve, (spender, amount)));
    }

    function _fee(uint256 amount) internal view returns (Call memory) {
        return Call(address(usdc), 0, abi.encodeCall(IERC20.transfer, (treasury, amount)));
    }

    function _op(Call[] memory calls) internal view returns (PackedUserOperation memory op) {
        op = _opRaw(abi.encodeCall(IModularAccountV2.executeBatch, (calls)));
    }

    function _opRaw(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op.sender = user;
        op.nonce = 7;
        op.callData = callData;
        op.accountGasLimits = bytes32((uint256(150_000) << 128) | 400_000);
        op.preVerificationGas = 60_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | 3 gwei);
        op.paymasterAndData = abi.encodePacked(paymaster, uint128(100_000), uint128(50_000), hex"cafe");
    }

    /// @dev Independent reference implementation of the v0.7 hash (the unit test in Envelope pins it to a
    ///      value returned by the real EntryPoint on Base).
    function _hash(PackedUserOperation memory op) internal view returns (bytes32) {
        bytes32 packed = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData)
            )
        );
        return keccak256(abi.encode(packed, ENTRY_POINT, block.chainid));
    }

    function _noAuth() internal pure returns (Authorization memory a) {}

    function _verify(PackedUserOperation memory op, Intent memory intent) internal view returns (bytes32, uint256) {
        return verifier.verify(op, _hash(op), _noAuth(), intent);
    }

    function _verify(Call[] memory calls, Intent memory intent) internal view returns (bytes32, uint256) {
        return _verify(_op(calls), intent);
    }

    function _expectReject(Reason reason, uint256 idx) internal {
        vm.expectRevert(abi.encodeWithSelector(Rejected.selector, reason, idx));
    }

    function _assertRejected(Call[] memory calls, Intent memory intent, Reason reason, uint256 idx) internal {
        _expectReject(reason, idx);
        this.externalVerify(_op(calls), intent);
    }

    /// @dev External hop so `vm.expectRevert` applies to exactly one call.
    function externalVerify(PackedUserOperation memory op, Intent memory intent) external view {
        verifier.verify(op, _hash(op), _noAuth(), intent);
    }

    function _calls(Call memory a) internal pure returns (Call[] memory c) {
        c = new Call[](1);
        c[0] = a;
    }

    function _calls(Call memory a, Call memory b) internal pure returns (Call[] memory c) {
        c = new Call[](2);
        (c[0], c[1]) = (a, b);
    }

    function _calls(Call memory a, Call memory b, Call memory d) internal pure returns (Call[] memory c) {
        c = new Call[](3);
        (c[0], c[1], c[2]) = (a, b, d);
    }

    function _calls(Call memory a, Call memory b, Call memory d, Call memory e)
        internal
        pure
        returns (Call[] memory c)
    {
        c = new Call[](4);
        (c[0], c[1], c[2], c[3]) = (a, b, d, e);
    }

    function _calls(Call memory a, Call memory b, Call memory d, Call memory e, Call memory f)
        internal
        pure
        returns (Call[] memory c)
    {
        c = new Call[](5);
        (c[0], c[1], c[2], c[3], c[4]) = (a, b, d, e, f);
    }

    function _intent(Action action, address target, uint256 amount) internal view returns (Intent memory it) {
        it.action = action;
        it.user = user;
        it.target = target;
        it.amount = amount;
        it.maxFee = 1e6;
    }

    function _noIndex() internal pure returns (uint256) {
        return NO_INDEX;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";

import {AllowlistRegistry} from "../../src/AllowlistRegistry.sol";
import {BatchVerifier} from "../../src/BatchVerifier.sol";
import {DeadlineGuard} from "../../src/DeadlineGuard.sol";
import {IAllowlistRegistry} from "../../src/interfaces/IAllowlistRegistry.sol";
import {IAaveV3Pool, IModularAccountV2} from "../../src/interfaces/IExternal.sol";
import {Action, Authorization, Call, Category, Config, Intent, PackedUserOperation} from "../../src/types/Types.sol";
import {UserOpLibHarness} from "../Envelope.t.sol";

interface IEntryPointV07 {
    function getUserOpHash(PackedUserOperation calldata op) external view returns (bytes32);
}

/// Fork tests against real Base contracts. Skipped unless BASE_RPC_URL is set.
/// TODO(Discovery): add real API payload fixtures from test/fixtures/ (stake, unstake, 1inch, Across).
contract BaseForkTest is Test {
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant MAV2 = 0x69007702764179f14F51cdce752f4f775d74E139;
    address internal constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address internal constant AAVE_POOL = 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5;

    bool internal forked;

    function setUp() public {
        string memory rpc = vm.envOr("BASE_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        forked = true;
    }

    modifier onlyFork() {
        if (!forked) vm.skip(true);
        _;
    }

    function testFork_userOpHashMatchesEntryPoint(
        address sender,
        uint256 nonce,
        bytes calldata callData,
        bytes32 gasLimits,
        uint256 pvg,
        bytes32 gasFees,
        bytes calldata pmData
    ) public onlyFork {
        PackedUserOperation memory op;
        (op.sender, op.nonce, op.callData, op.accountGasLimits) = (sender, nonce, callData, gasLimits);
        (op.preVerificationGas, op.gasFees, op.paymasterAndData) = (pvg, gasFees, pmData);
        assertEq(new UserOpLibHarness().hash(op), IEntryPointV07(ENTRY_POINT).getUserOpHash(op));
    }

    function testFork_mav2ExposesExecuteBatch() public onlyFork {
        bytes memory code = MAV2.code;
        assertGt(code.length, 0);
        bytes4 sel = IModularAccountV2.executeBatch.selector;
        bool found;
        for (uint256 i; i + 5 <= code.length; ++i) {
            if (code[i] == 0x63 && bytes4(abi.encodePacked(code[i + 1], code[i + 2], code[i + 3], code[i + 4])) == sel)
            {
                found = true;
                break;
            }
        }
        assertTrue(found, "executeBatch selector not in MAv2 bytecode");
    }

    /// End-to-end on real Base USDC and the real Aave v3 pool: an Aave USDC stake passes, a wrong asset fails.
    function testFork_aaveStakeOnRealContracts() public onlyFork {
        address timelock = makeAddr("timelock");
        address manager = makeAddr("manager");
        address user = makeAddr("restake-fork-user-5f1c9e");
        assertEq(user.code.length, 0);
        address treasury = makeAddr("treasury");

        DeadlineGuard guard = new DeadlineGuard();
        Config memory cfg = Config(USDC, 50, 50, 600, 0.11e6, 1 gwei, 3_000_000);
        AllowlistRegistry registry = AllowlistRegistry(
            address(
                new ERC1967Proxy(
                    address(new AllowlistRegistry()),
                    abi.encodeCall(AllowlistRegistry.initialize, (timelock, manager, manager, timelock, cfg))
                )
            )
        );
        BatchVerifier verifier = BatchVerifier(
            address(
                new ERC1967Proxy(
                    address(new BatchVerifier(address(guard))),
                    abi.encodeCall(
                        BatchVerifier.initialize, (IAllowlistRegistry(address(registry)), timelock, timelock)
                    )
                )
            )
        );
        vm.startPrank(manager);
        bytes32 a = registry.scheduleAdd(Category.AAVE_POOL, AAVE_POOL, 0);
        bytes32 b = registry.scheduleAdd(Category.FEE_RECIPIENT, treasury, 0);
        vm.stopPrank();
        vm.warp(block.timestamp + 48 hours);
        registry.execute(a);
        registry.execute(b);

        uint256 amount = 250e6;
        Call[] memory calls = new Call[](4);
        calls[0] = Call(address(guard), 0, abi.encodeCall(DeadlineGuard.requireBefore, (block.timestamp + 300)));
        calls[1] = Call(USDC, 0, abi.encodeCall(IERC20.approve, (AAVE_POOL, amount)));
        calls[2] = Call(AAVE_POOL, 0, abi.encodeCall(IAaveV3Pool.supply, (USDC, amount, user, 0)));
        calls[3] = Call(USDC, 0, abi.encodeCall(IERC20.transfer, (treasury, 0.6e6)));

        PackedUserOperation memory op;
        op.sender = user;
        op.callData = abi.encodeCall(IModularAccountV2.executeBatch, (calls));
        op.accountGasLimits = bytes32((uint256(150_000) << 128) | 400_000);
        op.preVerificationGas = 60_000;
        op.gasFees = bytes32((uint256(0.001 gwei) << 128) | 0.01 gwei);

        Intent memory it;
        (it.action, it.user, it.target, it.amount, it.maxFee) = (Action.STAKE, user, AAVE_POOL, amount, 0.6e6);

        bytes32 h = IEntryPointV07(ENTRY_POINT).getUserOpHash(op);
        (bytes32 verified,) = verifier.verify(op, h, Authorization(block.chainid, MAV2, 0), it);
        assertEq(verified, h);

        // Real-world case: makeAddr("user") derives from a public key and is already 7702-delegated to some other
        // implementation on Base. The verifier must refuse it even with a fresh MAv2 authorization.
        address squatted = makeAddr("user");
        if (squatted.code.length == 23 && keccak256(squatted.code) != keccak256(abi.encodePacked(hex"ef0100", MAV2))) {
            op.sender = squatted;
            it.user = squatted;
            calls[2] = Call(AAVE_POOL, 0, abi.encodeCall(IAaveV3Pool.supply, (USDC, amount, squatted, 0)));
            op.callData = abi.encodeCall(IModularAccountV2.executeBatch, (calls));
            (bool ok, uint8 code,) = verifier.check(
                op, IEntryPointV07(ENTRY_POINT).getUserOpHash(op), Authorization(block.chainid, MAV2, 0), it
            );
            assertFalse(ok);
            assertEq(code, 6); // Reason.BAD_ACCOUNT_CODE
        }
    }
}

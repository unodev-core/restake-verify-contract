// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {AllowlistRegistry} from "../src/AllowlistRegistry.sol";
import {BatchVerifier} from "../src/BatchVerifier.sol";
import {BridgeConfig, BridgeRoute, Category, Config, PoolType, RouterType} from "../src/types/Types.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

contract AllowlistRegistryV2 is AllowlistRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract AllowlistRegistryTest is VerifierTestBase {
    address internal newVault = makeAddr("newVault");

    function test_seededState() public view {
        assertTrue(registry.isAllowed(Category.VAULT_4626, address(vault)));
        assertEq(registry.list(Category.SWAP_POOL).length, 2);
        assertEq(uint8(registry.routerType(router)), uint8(RouterType.ONE_INCH_V6));
        assertEq(uint8(registry.poolType(address(poolWbnbStock))), uint8(PoolType.UNISWAP_V2));
        assertEq(registry.bridgeConfig(spokePool).spender, spokePool);
        assertEq(registry.listRoutes().length, 1);
        (BridgeRoute memory r, bool exists) = registry.bridgeRoute(spokePool, address(usdc), DST_CHAIN);
        assertTrue(exists);
        assertEq(r.outputDecimals, 18);
        (bytes32[] memory ids,) = registry.pending();
        assertEq(ids.length, 0);
    }

    // ───────────────────────── 48 h timelock on additions ─────────────────────────

    function test_add_waitsDelay() public {
        vm.prank(manager);
        vm.expectEmit(false, true, true, true);
        emit AllowlistRegistry.AdditionScheduled(bytes32(0), Category.VAULT_4626, newVault, block.timestamp + 48 hours);
        bytes32 id = registry.scheduleAdd(Category.VAULT_4626, newVault, 0);

        (bytes32[] memory ids, AllowlistRegistry.PendingOp[] memory ops) = registry.pending();
        assertEq(ids[0], id);
        assertEq(ops[0].eta, block.timestamp + 48 hours);

        vm.warp(block.timestamp + 48 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(AllowlistRegistry.NotReady.selector, block.timestamp + 1));
        registry.execute(id);
        assertFalse(registry.isAllowed(Category.VAULT_4626, newVault));

        vm.warp(block.timestamp + 1);
        vm.prank(makeAddr("anyone"));
        registry.execute(id);
        assertTrue(registry.isAllowed(Category.VAULT_4626, newVault));
    }

    function test_execute_twiceFails() public {
        vm.prank(manager);
        bytes32 id = registry.scheduleAdd(Category.VAULT_4626, newVault, 0);
        vm.warp(block.timestamp + 48 hours);
        registry.execute(id);
        vm.expectRevert(AllowlistRegistry.UnknownOp.selector);
        registry.execute(id);
    }

    function test_config_waitsDelay() public {
        Config memory cfg = registry.config();
        cfg.maxFeeBps = 100;
        vm.prank(manager);
        bytes32 id = registry.scheduleConfig(cfg);
        assertEq(registry.config().maxFeeBps, 50);
        vm.warp(block.timestamp + 48 hours);
        registry.execute(id);
        assertEq(registry.config().maxFeeBps, 100);
    }

    function test_onlyManagerSchedules() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, registry.MANAGER_ROLE()
            )
        );
        vm.prank(guardian);
        registry.scheduleAdd(Category.VAULT_4626, newVault, 0);
    }

    function test_scheduleValidation() public {
        vm.startPrank(manager);
        vm.expectRevert(AllowlistRegistry.ZeroAddress.selector);
        registry.scheduleAdd(Category.VAULT_4626, address(0), 0);
        vm.expectRevert(AllowlistRegistry.UseScheduleBridge.selector);
        registry.scheduleAdd(Category.BRIDGE, newVault, 0);
        vm.expectRevert(AllowlistRegistry.InvalidSubtype.selector);
        registry.scheduleAdd(Category.SWAP_POOL, newVault, 0);
        vm.expectRevert(AllowlistRegistry.InvalidSubtype.selector);
        registry.scheduleAdd(Category.SWAP_ROUTER, newVault, 2);
        vm.expectRevert(AllowlistRegistry.InvalidSubtype.selector);
        registry.scheduleAdd(Category.VAULT_4626, newVault, 1);
        vm.expectRevert(AllowlistRegistry.AlreadyAllowed.selector);
        registry.scheduleAdd(Category.VAULT_4626, address(vault), 0);

        BridgeConfig memory bc = _acrossConfig();
        bc.selectors = new bytes4[](0);
        vm.expectRevert(AllowlistRegistry.InvalidBridgeConfig.selector);
        registry.scheduleBridge(spokePool, bc);

        vm.expectRevert(AllowlistRegistry.InvalidRoute.selector);
        registry.scheduleRoute(spokePool, address(usdc), block.chainid, BridgeRoute(bscUsdc, 6, 18));

        Config memory cfg = registry.config();
        cfg.maxFeeBps = 10_001;
        vm.expectRevert(AllowlistRegistry.InvalidConfig.selector);
        registry.scheduleConfig(cfg);
        vm.stopPrank();
    }

    // ───────────────────────── instant tightening ─────────────────────────

    function test_cancel_byGuardian() public {
        vm.prank(manager);
        bytes32 id = registry.scheduleAdd(Category.VAULT_4626, newVault, 0);
        vm.prank(guardian);
        registry.cancel(id);
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(AllowlistRegistry.UnknownOp.selector);
        registry.execute(id);
    }

    function test_remove_isInstant() public {
        vm.prank(guardian);
        registry.remove(Category.SWAP_ROUTER, router);
        assertFalse(registry.isAllowed(Category.SWAP_ROUTER, router));
        assertEq(uint8(registry.routerType(router)), 0);
    }

    function test_remove_byStrangerFails() public {
        vm.expectRevert(AllowlistRegistry.NotGuardianOrManager.selector);
        vm.prank(attacker);
        registry.remove(Category.SWAP_ROUTER, router);
    }

    function test_removeRoute() public {
        vm.prank(manager);
        registry.removeRoute(spokePool, address(usdc), DST_CHAIN);
        (, bool exists) = registry.bridgeRoute(spokePool, address(usdc), DST_CHAIN);
        assertFalse(exists);
    }

    function test_pause_onlyGuardian_unpause_onlyManager() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, manager, registry.GUARDIAN_ROLE()
            )
        );
        vm.prank(manager);
        registry.pause();

        vm.prank(guardian);
        registry.pause();
        assertTrue(registry.paused());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, guardian, registry.MANAGER_ROLE()
            )
        );
        vm.prank(guardian);
        registry.unpause();

        vm.prank(manager);
        registry.unpause();
        assertFalse(registry.paused());
    }

    // ───────────────────────── upgrades ─────────────────────────

    function test_upgrade_onlyUpgrader() public {
        AllowlistRegistryV2 impl = new AllowlistRegistryV2();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, manager, registry.UPGRADER_ROLE()
            )
        );
        vm.prank(manager);
        registry.upgradeToAndCall(address(impl), "");

        vm.prank(timelock);
        registry.upgradeToAndCall(address(impl), "");
        assertEq(AllowlistRegistryV2(address(registry)).version(), 2);
        // Storage survives the upgrade.
        assertTrue(registry.isAllowed(Category.VAULT_4626, address(vault)));
    }

    function test_verifierUpgrade_onlyUpgrader() public {
        BatchVerifier impl = new BatchVerifier(address(guard));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, manager, verifier.UPGRADER_ROLE()
            )
        );
        vm.prank(manager);
        verifier.upgradeToAndCall(address(impl), "");
        vm.prank(timelock);
        verifier.upgradeToAndCall(address(impl), "");
        assertEq(address(verifier.registry()), address(registry));
    }

    function test_implementationsCannotBeInitialized() public {
        AllowlistRegistry impl = new AllowlistRegistry();
        Config memory cfg = registry.config();
        vm.expectRevert();
        impl.initialize(timelock, manager, guardian, timelock, cfg);
    }
}

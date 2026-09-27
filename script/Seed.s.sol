// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";

import {AllowlistRegistry} from "../src/AllowlistRegistry.sol";
import {IAcrossSpokePool} from "../src/interfaces/IExternal.sol";
import {BridgeConfig, BridgeRoute, BridgeType, Category, PoolType, RouterType} from "../src/types/Types.sol";

/// @notice Builds the initial `schedule*` calls for a chain from script/config/<chainid>.json.
///
/// MANAGER is a Safe, so by default this only prints `(to, data)` pairs to paste into the Safe Transaction Builder.
/// With BROADCAST=true (testnets, where the manager is an EOA) it sends them. After 48 h, anyone runs
/// `registry.execute(id)` for each scheduled id (see the `ChangeScheduled` events).
///
///   REGISTRY=0x... forge script script/Seed.s.sol --rpc-url base
contract Seed is Script {
    AllowlistRegistry internal registry;
    string internal json;
    bool internal broadcast;

    function run() external {
        registry = AllowlistRegistry(vm.envAddress("REGISTRY"));
        broadcast = vm.envOr("BROADCAST", false);
        json = vm.readFile(string.concat("script/config/", vm.toString(block.chainid), ".json"));

        if (broadcast) vm.startBroadcast();
        _addAll(".allowlist.paymasters", Category.PAYMASTER, 0);
        _addAll(".allowlist.vaults4626", Category.VAULT_4626, 0);
        _addAll(".allowlist.aavePools", Category.AAVE_POOL, 0);
        _addAll(".allowlist.assets", Category.ASSET, 0);
        _addAll(".allowlist.ondoTokens", Category.ONDO_TOKEN, 0);
        _addAll(".allowlist.oneInchRouters", Category.SWAP_ROUTER, uint8(RouterType.ONE_INCH_V6));
        _addAll(".allowlist.uniswapV2Pools", Category.SWAP_POOL, uint8(PoolType.UNISWAP_V2));
        _addAll(".allowlist.uniswapV3Pools", Category.SWAP_POOL, uint8(PoolType.UNISWAP_V3));
        _addAll(".allowlist.feeRecipients", Category.FEE_RECIPIENT, 0);
        _bridges();
        if (broadcast) vm.stopBroadcast();
    }

    function _addAll(string memory key, Category cat, uint8 subtype) internal {
        address[] memory addrs = vm.parseJsonAddressArray(json, key);
        for (uint256 i; i < addrs.length; ++i) {
            _send(abi.encodeCall(AllowlistRegistry.scheduleAdd, (cat, addrs[i], subtype)));
        }
    }

    function _bridges() internal {
        if (!vm.keyExistsJson(json, ".across.spokePool")) return;
        address spoke = vm.parseJsonAddress(json, ".across.spokePool");
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = IAcrossSpokePool.deposit.selector;
        BridgeConfig memory bc = BridgeConfig({
            bridgeType: BridgeType.ACROSS,
            spender: spoke,
            maxFillWindow: uint32(vm.parseJsonUint(json, ".across.maxFillWindow")),
            maxQuoteAge: uint32(vm.parseJsonUint(json, ".across.maxQuoteAge")),
            selectors: sels,
            integratorSuffix: vm.parseJsonBytes(json, ".across.integratorSuffix")
        });
        _send(abi.encodeCall(AllowlistRegistry.scheduleBridge, (spoke, bc)));

        address inputToken = vm.parseJsonAddress(json, ".across.route.inputToken");
        BridgeRoute memory route = BridgeRoute({
            outputToken: bytes32(uint256(uint160(vm.parseJsonAddress(json, ".across.route.outputToken")))),
            inputDecimals: uint8(vm.parseJsonUint(json, ".across.route.inputDecimals")),
            outputDecimals: uint8(vm.parseJsonUint(json, ".across.route.outputDecimals"))
        });
        uint256 dst = vm.parseJsonUint(json, ".across.route.dstChainId");
        _send(abi.encodeCall(AllowlistRegistry.scheduleRoute, (spoke, inputToken, dst, route)));
    }

    function _send(bytes memory data) internal {
        if (broadcast) {
            (bool ok, bytes memory ret) = address(registry).call(data);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        } else {
            console.log("to  ", address(registry));
            console.logBytes(data);
        }
    }
}

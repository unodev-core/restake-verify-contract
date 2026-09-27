// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Script, console} from "forge-std/Script.sol";
import {Options, Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

import {AllowlistRegistry} from "../src/AllowlistRegistry.sol";
import {BatchVerifier} from "../src/BatchVerifier.sol";
import {DeadlineGuard} from "../src/DeadlineGuard.sol";
import {IAllowlistRegistry} from "../src/interfaces/IAllowlistRegistry.sol";
import {Config} from "../src/types/Types.sol";

/// @notice Deploys one chain's stack (§5): DeadlineGuard (CREATE2, same address on every chain), a 48 h
///         TimelockController, and the AllowlistRegistry and BatchVerifier UUPS proxies, validated for upgrade safety.
///
/// Env: PROPOSER_SAFE (timelock proposer + canceller), MANAGER_SAFE, GUARDIAN_SAFE, and the chain config file
///      script/config/<chainid>.json (fee token, flat fee, gas caps).
///
///   forge script script/Deploy.s.sol --rpc-url base --broadcast --verify
contract Deploy is Script {
    bytes32 internal constant GUARD_SALT = keccak256("restake.DeadlineGuard.v1");
    uint256 internal constant TIMELOCK_DELAY = 48 hours;

    struct Deployment {
        DeadlineGuard guard;
        TimelockController timelock;
        AllowlistRegistry registry;
        BatchVerifier verifier;
    }

    function run() external returns (Deployment memory d) {
        address proposer = vm.envAddress("PROPOSER_SAFE");
        address manager = vm.envAddress("MANAGER_SAFE");
        address guardian = vm.envAddress("GUARDIAN_SAFE");
        Config memory cfg = loadConfig();

        vm.startBroadcast();
        d.guard = _guard();

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1); // address(0): anyone executes once the delay has passed
        d.timelock = new TimelockController(TIMELOCK_DELAY, proposers, executors, address(0));

        d.registry = AllowlistRegistry(
            Upgrades.deployUUPSProxy(
                "AllowlistRegistry.sol",
                abi.encodeCall(
                    AllowlistRegistry.initialize, (address(d.timelock), manager, guardian, address(d.timelock), cfg)
                )
            )
        );

        Options memory opts;
        opts.constructorData = abi.encode(address(d.guard));
        d.verifier = BatchVerifier(
            Upgrades.deployUUPSProxy(
                "BatchVerifier.sol",
                abi.encodeCall(
                    BatchVerifier.initialize,
                    (IAllowlistRegistry(address(d.registry)), address(d.timelock), address(d.timelock))
                ),
                opts
            )
        );
        vm.stopBroadcast();

        console.log("DeadlineGuard     ", address(d.guard));
        console.log("TimelockController", address(d.timelock));
        console.log("AllowlistRegistry ", address(d.registry));
        console.log("BatchVerifier     ", address(d.verifier));
    }

    function loadConfig() public view returns (Config memory cfg) {
        string memory json = vm.readFile(string.concat("script/config/", vm.toString(block.chainid), ".json"));
        cfg = Config({
            feeToken: vm.parseJsonAddress(json, ".config.feeToken"),
            maxFeeBps: uint16(vm.parseJsonUint(json, ".config.maxFeeBps")),
            maxBridgeFeeBps: uint16(vm.parseJsonUint(json, ".config.maxBridgeFeeBps")),
            maxBatchTtl: uint32(vm.parseJsonUint(json, ".config.maxBatchTtl")),
            flatFee: vm.parseJsonUint(json, ".config.flatFee"),
            maxFeePerGas: uint128(vm.parseJsonUint(json, ".config.maxFeePerGas")),
            maxTotalGas: uint128(vm.parseJsonUint(json, ".config.maxTotalGas"))
        });
    }

    /// @dev CREATE2 through the canonical deployer, so the backend uses one guard address on every chain.
    function _guard() internal returns (DeadlineGuard guard) {
        address predicted = vm.computeCreate2Address(GUARD_SALT, keccak256(type(DeadlineGuard).creationCode));
        if (predicted.code.length != 0) return DeadlineGuard(predicted);
        guard = new DeadlineGuard{salt: GUARD_SALT}();
    }
}

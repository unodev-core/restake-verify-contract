// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BridgeConfig, BridgeRoute, Category, Config, PoolType, RouteEntry, RouterType} from "../types/Types.sol";

/// @notice Read interface of the per-chain allowlist, as used by BatchVerifier and partners.
interface IAllowlistRegistry {
    function isAllowed(Category cat, address addr) external view returns (bool);
    function list(Category cat) external view returns (address[] memory);
    function routerType(address router) external view returns (RouterType);
    function poolType(address pool) external view returns (PoolType);
    function bridgeConfig(address bridge) external view returns (BridgeConfig memory);
    function bridgeRoute(address bridge, address inputToken, uint256 dstChainId)
        external
        view
        returns (BridgeRoute memory route, bool exists);
    function listRoutes() external view returns (RouteEntry[] memory);
    function config() external view returns (Config memory);
    function paused() external view returns (bool);
}

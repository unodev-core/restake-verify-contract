// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAllowlistRegistry} from "./interfaces/IAllowlistRegistry.sol";
import {
    BridgeConfig,
    BridgeRoute,
    BridgeType,
    Category,
    Config,
    PoolType,
    RouteEntry,
    RouterType
} from "./types/Types.sol";

/// @title AllowlistRegistry
/// @notice Per-chain allowlist read by BatchVerifier (§4). Anything that loosens the rules (adds, config changes)
///         waits `DELAY` and is announced on-chain; anything that tightens them (removes, cancel, pause) is instant.
contract AllowlistRegistry is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    IAllowlistRegistry
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant DELAY = 48 hours;

    enum OpKind {
        ADD_ADDRESS,
        SET_BRIDGE,
        SET_ROUTE,
        SET_CONFIG
    }

    struct PendingOp {
        OpKind kind;
        uint64 eta;
        bytes payload;
    }

    /// @custom:storage-location erc7201:restake.storage.AllowlistRegistry
    struct RegistryStorage {
        mapping(Category => EnumerableSet.AddressSet) allowed;
        mapping(address => RouterType) routerType;
        mapping(address => PoolType) poolType;
        mapping(address => BridgeConfig) bridgeConfig;
        mapping(bytes32 => RouteEntry) routes;
        EnumerableSet.Bytes32Set routeKeys;
        Config config;
        mapping(bytes32 => PendingOp) pending;
        EnumerableSet.Bytes32Set pendingIds;
        uint256 opNonce;
    }

    // keccak256(abi.encode(uint256(keccak256("restake.storage.AllowlistRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_LOCATION = 0x566730d7d68f750b7ed1b031a1d977961c296a8ea44bf8719fe336ed11abdf00;

    event AdditionScheduled(bytes32 indexed id, Category indexed cat, address indexed addr, uint256 eta);
    event ChangeScheduled(bytes32 indexed id, OpKind indexed kind, uint256 eta, bytes payload);
    event ChangeExecuted(bytes32 indexed id, OpKind indexed kind);
    event ChangeCancelled(bytes32 indexed id);
    event Added(Category indexed cat, address indexed addr, uint8 subtype);
    event Removed(Category indexed cat, address indexed addr);
    event BridgeConfigSet(address indexed bridge);
    event RouteSet(bytes32 indexed key, address indexed bridge, address indexed inputToken, uint256 dstChainId);
    event RouteRemoved(bytes32 indexed key);
    event ConfigSet(Config config);

    error ZeroAddress();
    error InvalidSubtype();
    error InvalidConfig();
    error InvalidBridgeConfig();
    error InvalidRoute();
    error UseScheduleBridge();
    error AlreadyAllowed();
    error NotAllowed();
    error UnknownOp();
    error NotReady(uint256 eta);
    error NotGuardianOrManager();

    modifier onlyGuardianOrManager() {
        if (!hasRole(GUARDIAN_ROLE, msg.sender) && !hasRole(MANAGER_ROLE, msg.sender)) revert NotGuardianOrManager();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param admin Holder of DEFAULT_ADMIN_ROLE. Must be the TimelockController: an admin can grant UPGRADER_ROLE.
    /// @param upgrader Holder of UPGRADER_ROLE. Must be the TimelockController.
    function initialize(address admin, address manager, address guardian, address upgrader, Config calldata cfg)
        external
        initializer
    {
        if (admin == address(0) || manager == address(0) || guardian == address(0) || upgrader == address(0)) {
            revert ZeroAddress();
        }
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(GUARDIAN_ROLE, guardian);
        _grantRole(UPGRADER_ROLE, upgrader);
        _validateConfig(cfg);
        _s().config = cfg;
        emit ConfigSet(cfg);
    }

    // ───────────────────────────── scheduling (48 h) ─────────────────────────────

    /// @notice Schedule adding `addr` to `cat`. `subtype` is the RouterType for SWAP_ROUTER, the PoolType for
    ///         SWAP_POOL, and 0 otherwise. Bridges are added with `scheduleBridge`.
    function scheduleAdd(Category cat, address addr, uint8 subtype)
        external
        onlyRole(MANAGER_ROLE)
        returns (bytes32 id)
    {
        _validateAdd(cat, addr, subtype);
        id = _schedule(OpKind.ADD_ADDRESS, abi.encode(cat, addr, subtype));
        emit AdditionScheduled(id, cat, addr, block.timestamp + DELAY);
    }

    /// @notice Schedule adding a bridge, or replacing its config row.
    function scheduleBridge(address bridge, BridgeConfig calldata cfg)
        external
        onlyRole(MANAGER_ROLE)
        returns (bytes32 id)
    {
        if (bridge == address(0)) revert ZeroAddress();
        _validateBridgeConfig(cfg);
        id = _schedule(OpKind.SET_BRIDGE, abi.encode(bridge, cfg));
        emit AdditionScheduled(id, Category.BRIDGE, bridge, block.timestamp + DELAY);
    }

    /// @notice Schedule adding or changing the route `(bridge, inputToken, dstChainId)`.
    function scheduleRoute(address bridge, address inputToken, uint256 dstChainId, BridgeRoute calldata route)
        external
        onlyRole(MANAGER_ROLE)
        returns (bytes32 id)
    {
        _validateRoute(bridge, inputToken, dstChainId, route);
        id = _schedule(OpKind.SET_ROUTE, abi.encode(bridge, inputToken, dstChainId, route));
    }

    /// @notice Schedule a change of the config values (fee caps, TTL, gas caps).
    function scheduleConfig(Config calldata cfg) external onlyRole(MANAGER_ROLE) returns (bytes32 id) {
        _validateConfig(cfg);
        id = _schedule(OpKind.SET_CONFIG, abi.encode(cfg));
    }

    /// @notice Apply a scheduled change once its eta has passed. Callable by anyone.
    function execute(bytes32 id) external {
        RegistryStorage storage s = _s();
        PendingOp memory op = s.pending[id];
        if (op.eta == 0) revert UnknownOp();
        if (block.timestamp < op.eta) revert NotReady(op.eta);
        delete s.pending[id];
        // slither-disable-next-line unused-return (idempotent set update)
        s.pendingIds.remove(id);

        if (op.kind == OpKind.ADD_ADDRESS) {
            (Category cat, address addr, uint8 subtype) = abi.decode(op.payload, (Category, address, uint8));
            _validateAdd(cat, addr, subtype);
            // slither-disable-next-line unused-return (idempotent set update)
            s.allowed[cat].add(addr);
            if (cat == Category.SWAP_ROUTER) s.routerType[addr] = RouterType(subtype);
            if (cat == Category.SWAP_POOL) s.poolType[addr] = PoolType(subtype);
            emit Added(cat, addr, subtype);
        } else if (op.kind == OpKind.SET_BRIDGE) {
            (address bridge, BridgeConfig memory cfg) = abi.decode(op.payload, (address, BridgeConfig));
            // slither-disable-next-line unused-return (idempotent set update)
            s.allowed[Category.BRIDGE].add(bridge);
            s.bridgeConfig[bridge] = cfg;
            emit BridgeConfigSet(bridge);
        } else if (op.kind == OpKind.SET_ROUTE) {
            (address bridge, address inputToken, uint256 dstChainId, BridgeRoute memory route) =
                abi.decode(op.payload, (address, address, uint256, BridgeRoute));
            bytes32 key = routeKey(bridge, inputToken, dstChainId);
            s.routes[key] = RouteEntry(bridge, inputToken, dstChainId, route);
            // slither-disable-next-line unused-return (idempotent set update)
            s.routeKeys.add(key);
            emit RouteSet(key, bridge, inputToken, dstChainId);
        } else {
            Config memory cfg = abi.decode(op.payload, (Config));
            s.config = cfg;
            emit ConfigSet(cfg);
        }
        emit ChangeExecuted(id, op.kind);
    }

    // ───────────────────────────── instant tightening ─────────────────────────────

    function cancel(bytes32 id) external onlyGuardianOrManager {
        RegistryStorage storage s = _s();
        if (s.pending[id].eta == 0) revert UnknownOp();
        delete s.pending[id];
        // slither-disable-next-line unused-return (idempotent set update)
        s.pendingIds.remove(id);
        emit ChangeCancelled(id);
    }

    /// @notice Remove an address immediately. Removing a bridge also drops its config and all its routes, so a
    ///         later re-add cannot silently revive old routes.
    function remove(Category cat, address addr) external onlyGuardianOrManager {
        RegistryStorage storage s = _s();
        if (!s.allowed[cat].remove(addr)) revert NotAllowed();
        if (cat == Category.SWAP_ROUTER) delete s.routerType[addr];
        if (cat == Category.SWAP_POOL) delete s.poolType[addr];
        if (cat == Category.BRIDGE) {
            delete s.bridgeConfig[addr];
            bytes32[] memory keys = s.routeKeys.values();
            for (uint256 i; i < keys.length; ++i) {
                if (s.routes[keys[i]].bridge == addr) _removeRoute(s, keys[i]);
            }
        }
        emit Removed(cat, addr);
    }

    function removeRoute(address bridge, address inputToken, uint256 dstChainId) external onlyGuardianOrManager {
        RegistryStorage storage s = _s();
        bytes32 key = routeKey(bridge, inputToken, dstChainId);
        if (!s.routeKeys.contains(key)) revert NotAllowed();
        _removeRoute(s, key);
    }

    /// @notice Make every verification fail.
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(MANAGER_ROLE) {
        _unpause();
    }

    // ───────────────────────────── views ─────────────────────────────

    function isAllowed(Category cat, address addr) external view returns (bool) {
        return _s().allowed[cat].contains(addr);
    }

    function list(Category cat) external view returns (address[] memory) {
        return _s().allowed[cat].values();
    }

    function routerType(address router) external view returns (RouterType) {
        return _s().routerType[router];
    }

    function poolType(address pool) external view returns (PoolType) {
        return _s().poolType[pool];
    }

    function bridgeConfig(address bridge) external view returns (BridgeConfig memory) {
        return _s().bridgeConfig[bridge];
    }

    function bridgeRoute(address bridge, address inputToken, uint256 dstChainId)
        external
        view
        returns (BridgeRoute memory route, bool exists)
    {
        RegistryStorage storage s = _s();
        bytes32 key = routeKey(bridge, inputToken, dstChainId);
        exists = s.routeKeys.contains(key);
        if (exists) route = s.routes[key].route;
    }

    function listRoutes() external view returns (RouteEntry[] memory entries) {
        RegistryStorage storage s = _s();
        uint256 n = s.routeKeys.length();
        entries = new RouteEntry[](n);
        for (uint256 i; i < n; ++i) {
            entries[i] = s.routes[s.routeKeys.at(i)];
        }
    }

    function pending() external view returns (bytes32[] memory ids, PendingOp[] memory ops) {
        RegistryStorage storage s = _s();
        ids = s.pendingIds.values();
        ops = new PendingOp[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            ops[i] = s.pending[ids[i]];
        }
    }

    function config() external view returns (Config memory) {
        return _s().config;
    }

    function paused() public view override(IAllowlistRegistry, PausableUpgradeable) returns (bool) {
        return super.paused();
    }

    function routeKey(address bridge, address inputToken, uint256 dstChainId) public pure returns (bytes32) {
        return keccak256(abi.encode(bridge, inputToken, dstChainId));
    }

    // ───────────────────────────── internals ─────────────────────────────

    function _schedule(OpKind kind, bytes memory payload) private returns (bytes32 id) {
        RegistryStorage storage s = _s();
        id = keccak256(abi.encode(kind, payload, s.opNonce++));
        uint64 eta = uint64(block.timestamp + DELAY);
        s.pending[id] = PendingOp(kind, eta, payload);
        // slither-disable-next-line unused-return (idempotent set update)
        s.pendingIds.add(id);
        emit ChangeScheduled(id, kind, eta, payload);
    }

    function _removeRoute(RegistryStorage storage s, bytes32 key) private {
        delete s.routes[key];
        // slither-disable-next-line unused-return (idempotent set update)
        s.routeKeys.remove(key);
        emit RouteRemoved(key);
    }

    function _validateAdd(Category cat, address addr, uint8 subtype) private view {
        if (addr == address(0)) revert ZeroAddress();
        if (cat == Category.BRIDGE) revert UseScheduleBridge();
        if (_s().allowed[cat].contains(addr)) revert AlreadyAllowed();
        if (cat == Category.SWAP_ROUTER) {
            if (subtype == uint8(RouterType.NONE) || subtype > uint8(type(RouterType).max)) revert InvalidSubtype();
        } else if (cat == Category.SWAP_POOL) {
            if (subtype == uint8(PoolType.NONE) || subtype > uint8(type(PoolType).max)) revert InvalidSubtype();
        } else if (subtype != 0) {
            revert InvalidSubtype();
        }
    }

    function _validateBridgeConfig(BridgeConfig calldata cfg) private pure {
        if (
            cfg.bridgeType == BridgeType.NONE || cfg.spender == address(0) || cfg.maxFillWindow == 0
                || cfg.selectors.length == 0
        ) revert InvalidBridgeConfig();
    }

    function _validateRoute(address bridge, address inputToken, uint256 dstChainId, BridgeRoute calldata route)
        private
        view
    {
        if (bridge == address(0) || inputToken == address(0)) revert ZeroAddress();
        if (
            dstChainId == 0 || dstChainId == block.chainid || route.outputToken == bytes32(0)
                || route.inputDecimals > 36 || route.outputDecimals > 36
        ) revert InvalidRoute();
    }

    function _validateConfig(Config calldata cfg) private pure {
        if (
            cfg.feeToken == address(0) || cfg.maxFeeBps > 10_000 || cfg.maxBridgeFeeBps > 10_000 || cfg.maxBatchTtl == 0
        ) revert InvalidConfig();
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    function _s() private pure returns (RegistryStorage storage s) {
        assembly {
            s.slot := STORAGE_LOCATION
        }
    }
}

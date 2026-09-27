// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IAaveV3Pool} from "../src/interfaces/IExternal.sol";
import {Reason} from "../src/types/Errors.sol";
import {Action, Call, Category, Intent} from "../src/types/Types.sol";
import {VerifierTestBase} from "./utils/VerifierTestBase.sol";

/// STAKE / UNSTAKE (ERC-4626 and Aave v3) plus the shared approval and fee rules.
contract VaultTest is VerifierTestBase {
    uint256 internal constant AMOUNT = 1000e6;
    uint256 internal constant FEE = 2.1e6; // 0.2% + $0.10

    function _deposit(uint256 amount, address receiver) internal view returns (Call memory) {
        return Call(address(vault), 0, abi.encodeCall(IERC4626.deposit, (amount, receiver)));
    }

    function _redeem(uint256 shares, address receiver, address owner) internal view returns (Call memory) {
        return Call(address(vault), 0, abi.encodeCall(IERC4626.redeem, (shares, receiver, owner)));
    }

    function _stakeIntent() internal view returns (Intent memory it) {
        it = _intent(Action.STAKE, address(vault), AMOUNT);
        it.maxFee = FEE;
    }

    function _unstakeIntent() internal view returns (Intent memory it) {
        it = _intent(Action.UNSTAKE, address(vault), AMOUNT);
        it.maxFee = FEE;
    }

    // ───────────────────────── STAKE ERC-4626 ─────────────────────────

    function test_stake_ok() public view {
        _verify(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(FEE)),
            _stakeIntent()
        );
    }

    function test_stake_withoutFee_ok() public view {
        _verify(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user)),
            _stakeIntent()
        );
    }

    function test_stake_usdtStyleReset_ok() public view {
        _verify(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), address(vault), 0),
                _approve(address(usdc), address(vault), AMOUNT),
                _deposit(AMOUNT, user),
                _fee(FEE)
            ),
            _stakeIntent()
        );
    }

    function test_stake_resetMustBeZero() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), address(vault), 1),
                _approve(address(usdc), address(vault), AMOUNT),
                _deposit(AMOUNT, user)
            ),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }

    function test_stake_threeApprovesRejected() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), address(vault), 0),
                _approve(address(usdc), address(vault), 0),
                _approve(address(usdc), address(vault), AMOUNT),
                _deposit(AMOUNT, user)
            ),
            _stakeIntent(),
            Reason.UNEXPECTED_CALL,
            3
        );
    }

    function test_stake_infiniteApprove() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), type(uint256).max), _deposit(AMOUNT, user)),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }

    function test_stake_approveAmountDiffers() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT + 1), _deposit(AMOUNT, user)),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }

    function test_stake_approveToAttacker() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), attacker, AMOUNT), _deposit(AMOUNT, user)),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }

    function test_stake_approveWrongToken() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(dai), address(vault), AMOUNT), _deposit(AMOUNT, user)),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            1
        );
    }

    function test_stake_approveTrailingBytes() public {
        Call memory a = _approve(address(usdc), address(vault), AMOUNT);
        a.data = abi.encodePacked(a.data, hex"00");
        _assertRejected(_calls(_deadlineCall(), a, _deposit(AMOUNT, user)), _stakeIntent(), Reason.MALFORMED_CALL, 1);
    }

    function test_stake_receiverIsAttacker() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, attacker)),
            _stakeIntent(),
            Reason.BAD_RECEIVER,
            2
        );
    }

    function test_stake_amountDiffersFromIntent() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT - 1, user)),
            _stakeIntent(),
            Reason.BAD_AMOUNT,
            2
        );
    }

    function test_stake_mintRejected() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), address(vault), AMOUNT),
                Call(address(vault), 0, abi.encodeCall(IERC4626.mint, (AMOUNT, user)))
            ),
            _stakeIntent(),
            Reason.BAD_SELECTOR,
            2
        );
    }

    function test_stake_unlistedVault() public {
        Intent memory it = _stakeIntent();
        address fake = makeAddr("fakeVault");
        it.target = fake;
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), fake, AMOUNT),
                Call(fake, 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user)))
            ),
            it,
            Reason.TARGET_NOT_ALLOWED,
            2
        );
    }

    function test_stake_mainCallNotToIntentTarget() public {
        Intent memory it = _stakeIntent();
        it.target = address(daiVault);
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user)),
            it,
            Reason.TARGET_NOT_ALLOWED,
            2
        );
    }

    function test_stake_nonUsdcVault() public {
        Intent memory it = _stakeIntent();
        it.target = address(daiVault);
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(dai), address(daiVault), AMOUNT),
                Call(address(daiVault), 0, abi.encodeCall(IERC4626.deposit, (AMOUNT, user)))
            ),
            it,
            Reason.UNSUPPORTED_ASSET,
            2
        );
    }

    function test_stake_standingExactAllowance_ok() public {
        vm.prank(user);
        usdc.approve(address(vault), AMOUNT);
        _verify(_calls(_deadlineCall(), _deposit(AMOUNT, user)), _stakeIntent());
    }

    function test_stake_standingLargerAllowance_needsRevoke() public {
        vm.prank(user);
        usdc.approve(address(vault), AMOUNT * 2);
        _assertRejected(_calls(_deadlineCall(), _deposit(AMOUNT, user)), _stakeIntent(), Reason.RESIDUAL_ALLOWANCE, 1);
        _verify(
            _calls(_deadlineCall(), _deposit(AMOUNT, user), _approve(address(usdc), address(vault), 0)), _stakeIntent()
        );
    }

    function test_stake_standingInfiniteAllowance_needsRevoke() public {
        vm.prank(user);
        usdc.approve(address(vault), type(uint256).max);
        _assertRejected(_calls(_deadlineCall(), _deposit(AMOUNT, user)), _stakeIntent(), Reason.RESIDUAL_ALLOWANCE, 1);
    }

    function test_stake_revokeAfterFee() public {
        vm.prank(user);
        usdc.approve(address(vault), type(uint256).max);
        // fee is not last -> it is parsed as an unexpected call after the revoke slot
        _assertRejected(
            _calls(_deadlineCall(), _deposit(AMOUNT, user), _fee(FEE), _approve(address(usdc), address(vault), 0)),
            _stakeIntent(),
            Reason.UNEXPECTED_CALL,
            2
        );
    }

    function test_stake_nonZeroRevoke() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), address(vault), AMOUNT),
                _deposit(AMOUNT, user),
                _approve(address(usdc), address(vault), 1)
            ),
            _stakeIntent(),
            Reason.BAD_APPROVE,
            3
        );
    }

    // ───────────────────────── fee ─────────────────────────

    function test_fee_notLast() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _fee(FEE), _deposit(AMOUNT, user)),
            _stakeIntent(),
            Reason.UNEXPECTED_CALL,
            2
        );
    }

    function test_fee_wrongToken() public {
        Call memory fee = Call(address(dai), 0, abi.encodeCall(IERC20.transfer, (treasury, FEE)));
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), fee),
            _stakeIntent(),
            Reason.UNEXPECTED_CALL,
            3
        );
    }

    function test_fee_unlistedRecipient() public {
        Call memory fee = Call(address(usdc), 0, abi.encodeCall(IERC20.transfer, (attacker, FEE)));
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), fee),
            _stakeIntent(),
            Reason.BAD_FEE,
            3
        );
    }

    function test_fee_aboveIntentMaxFee() public {
        _assertRejected(
            _calls(
                _deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(FEE + 1)
            ),
            _stakeIntent(),
            Reason.FEE_TOO_HIGH,
            3
        );
    }

    function test_fee_notAllowedWhenMaxFeeZero() public {
        Intent memory it = _stakeIntent();
        it.maxFee = 0;
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(0)),
            it,
            Reason.FEE_TOO_HIGH,
            3
        );
    }

    function test_fee_aboveBackstopCap() public {
        // cap = 0.11 + 1000 * 0.5% = 5.11 USDC; the partner's maxFee is careless
        Intent memory it = _stakeIntent();
        it.maxFee = 100e6;
        uint256 cap = FLAT_FEE + AMOUNT * 50 / 10_000;
        _verify(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(cap)),
            it
        );
        _assertRejected(
            _calls(
                _deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(cap + 1)
            ),
            it,
            Reason.FEE_TOO_HIGH,
            3
        );
    }

    function test_fee_removedRecipientFailsImmediately() public {
        vm.prank(guardian);
        registry.remove(Category.FEE_RECIPIENT, treasury);
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(usdc), address(vault), AMOUNT), _deposit(AMOUNT, user), _fee(FEE)),
            _stakeIntent(),
            Reason.BAD_FEE,
            3
        );
    }

    // ───────────────────────── UNSTAKE ERC-4626 ─────────────────────────

    function test_unstake_redeem_zeroAllowance_ok() public view {
        _verify(_calls(_deadlineCall(), _redeem(AMOUNT, user, user), _fee(FEE)), _unstakeIntent());
    }

    function test_unstake_redundantRevoke_ok() public view {
        _verify(
            _calls(_deadlineCall(), _redeem(AMOUNT, user, user), _approve(address(usdc), address(vault), 0), _fee(FEE)),
            _unstakeIntent()
        );
    }

    function test_unstake_withoutRevokeOverAllowance() public {
        vm.prank(user);
        usdc.approve(address(vault), 1);
        _assertRejected(
            _calls(_deadlineCall(), _redeem(AMOUNT, user, user), _fee(FEE)),
            _unstakeIntent(),
            Reason.RESIDUAL_ALLOWANCE,
            1
        );
        _verify(
            _calls(_deadlineCall(), _redeem(AMOUNT, user, user), _approve(address(usdc), address(vault), 0), _fee(FEE)),
            _unstakeIntent()
        );
    }

    function test_unstake_wrongReceiver() public {
        _assertRejected(
            _calls(_deadlineCall(), _redeem(AMOUNT, attacker, user)), _unstakeIntent(), Reason.BAD_RECEIVER, 1
        );
    }

    function test_unstake_wrongOwner() public {
        _assertRejected(
            _calls(_deadlineCall(), _redeem(AMOUNT, user, attacker)), _unstakeIntent(), Reason.BAD_RECEIVER, 1
        );
    }

    function test_unstake_sharesDiffer() public {
        _assertRejected(
            _calls(_deadlineCall(), _redeem(AMOUNT + 1, user, user)), _unstakeIntent(), Reason.BAD_AMOUNT, 1
        );
    }

    function test_unstake_preApproveRejected() public {
        _assertRejected(
            _calls(_deadlineCall(), _approve(address(vault), attacker, AMOUNT), _redeem(AMOUNT, user, user)),
            _unstakeIntent(),
            Reason.UNEXPECTED_CALL,
            1
        );
    }

    function test_unstake_withdraw_ok() public view {
        _verify(
            _calls(
                _deadlineCall(),
                Call(address(vault), 0, abi.encodeCall(IERC4626.withdraw, (AMOUNT, user, user))),
                _fee(FEE)
            ),
            _unstakeIntent()
        );
    }

    function test_unstake_withdraw_burnsMoreSharesThanIntent() public {
        Intent memory it = _unstakeIntent();
        it.amount = AMOUNT - 1;
        _assertRejected(
            _calls(_deadlineCall(), Call(address(vault), 0, abi.encodeCall(IERC4626.withdraw, (AMOUNT, user, user)))),
            it,
            Reason.BAD_AMOUNT,
            1
        );
    }

    function test_unstake_feeCapUsesPreviewRedeem() public {
        Intent memory it = _unstakeIntent();
        it.maxFee = 100e6;
        uint256 cap = FLAT_FEE + vault.previewRedeem(AMOUNT) * 50 / 10_000;
        _assertRejected(_calls(_deadlineCall(), _redeem(AMOUNT, user, user), _fee(cap + 1)), it, Reason.FEE_TOO_HIGH, 2);
    }

    // ───────────────────────── Aave v3 ─────────────────────────

    function test_aave_stake_ok() public view {
        Intent memory it = _intent(Action.STAKE, aavePool, AMOUNT);
        it.maxFee = FEE;
        _verify(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), aavePool, AMOUNT),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.supply, (address(usdc), AMOUNT, user, 0))),
                _fee(FEE)
            ),
            it
        );
    }

    function test_aave_stake_onBehalfOfAttacker() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(usdc), aavePool, AMOUNT),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.supply, (address(usdc), AMOUNT, attacker, 0)))
            ),
            _intent(Action.STAKE, aavePool, AMOUNT),
            Reason.BAD_RECEIVER,
            2
        );
    }

    function test_aave_stake_nonUsdcAsset() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                _approve(address(dai), aavePool, AMOUNT),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.supply, (address(dai), AMOUNT, user, 0)))
            ),
            _intent(Action.STAKE, aavePool, AMOUNT),
            Reason.UNSUPPORTED_ASSET,
            2
        );
    }

    function test_aave_unstake_ok() public view {
        Intent memory it = _intent(Action.UNSTAKE, aavePool, AMOUNT);
        it.maxFee = FEE;
        _verify(
            _calls(
                _deadlineCall(),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.withdraw, (address(usdc), AMOUNT, user))),
                _fee(FEE)
            ),
            it
        );
    }

    function test_aave_unstake_wrongTo() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.withdraw, (address(usdc), AMOUNT, attacker)))
            ),
            _intent(Action.UNSTAKE, aavePool, AMOUNT),
            Reason.BAD_RECEIVER,
            1
        );
    }

    function test_aave_unstake_withdrawAllRejected() public {
        _assertRejected(
            _calls(
                _deadlineCall(),
                Call(aavePool, 0, abi.encodeCall(IAaveV3Pool.withdraw, (address(usdc), type(uint256).max, user)))
            ),
            _intent(Action.UNSTAKE, aavePool, type(uint256).max),
            Reason.BAD_AMOUNT,
            1
        );
    }
}

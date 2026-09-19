// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FeeVault, FeeVaultFactory} from "./FeeVault.sol";

/**
 * These tests exist to make the security claims in the README executable.
 *
 * Every "the platform cannot do X" sentence should have a test here that fails
 * if it stops being true. If you change the contracts and a test in the
 * ATTESTOR CANNOT or CREATE2 sections breaks, that is not a test to update —
 * it is a design property you just removed.
 *
 *   forge test -vvv
 */

/// Minimal ERC-20 for the token-claim paths.
contract MockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A token whose transfer returns nothing — plenty of real ones do this, and a
/// naive IERC20 call reverts on them. Anyone can send any token to a vault.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}

contract FeeVaultTest is Test {
    FeeVaultFactory factory;

    uint256 attestorKey = 0xA11CE;
    uint256 rogueKey = 0xBADBAD;
    address attestor;
    address admin = address(0xADD1);

    address creator = address(0xC0FFEE);
    address attacker = address(0xBAD);

    string constant X_ID = "1526383213";

    bytes32 constant BIND_TYPEHASH =
        keccak256("Bind(string xUserId,address owner,uint256 deadline,uint256 nonce)");

    function setUp() public {
        attestor = vm.addr(attestorKey);
        factory = new FeeVaultFactory(admin, attestor);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _sign(
        uint256 key,
        string memory xUserId,
        address owner,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(BIND_TYPEHASH, keccak256(bytes(xUserId)), owner, deadline, nonce));
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", factory.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _bind(address owner, uint256 nonce) internal returns (address vault) {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, X_ID, owner, deadline, nonce);
        return factory.bindOwner(X_ID, owner, deadline, nonce, sig);
    }

    // ==================================================================
    // CREATE2 — the address must be right BEFORE anything is deployed.
    //
    // This is the load-bearing property of the whole design. The site shows
    // people this address and fees get sent to it. If prediction and
    // deployment ever disagree, money goes somewhere nobody can reach.
    // ==================================================================

    function test_predictedAddressMatchesDeployed() public {
        address predicted = factory.predictVault(X_ID);
        address deployed = factory.deployVault(X_ID);
        assertEq(deployed, predicted, "CREATE2 prediction diverged from deployment");
    }

    function test_fundsSentBeforeDeploymentSurvive() public {
        address predicted = factory.predictVault(X_ID);

        // Fees arrive before anyone has spent gas deploying the vault.
        vm.deal(address(this), 5 ether);
        (bool ok, ) = predicted.call{value: 5 ether}("");
        assertTrue(ok, "could not pre-fund the predicted address");
        assertEq(predicted.balance, 5 ether);

        // Deploying later must not disturb the balance.
        address vault = factory.deployVault(X_ID);
        assertEq(vault, predicted);
        assertEq(vault.balance, 5 ether, "pre-deployment funds were lost");

        // And they are claimable.
        _bind(creator, 1);
        vm.prank(creator);
        FeeVault(payable(vault)).sweep(address(0));
        assertEq(creator.balance, 5 ether);
    }

    function test_differentAccountsGetDifferentVaults() public {
        assertTrue(factory.predictVault("111") != factory.predictVault("222"));
    }

    function test_deployIsIdempotent() public {
        address a = factory.deployVault(X_ID);
        address b = factory.deployVault(X_ID);
        assertEq(a, b, "second deploy should return the existing vault, not revert");
    }

    // ==================================================================
    // ATTESTOR CANNOT — the claims this design rests on.
    // ==================================================================

    function test_attestorCannotWithdraw() public {
        address vault = factory.deployVault(X_ID);
        vm.deal(vault, 1 ether);
        _bind(creator, 1);

        vm.prank(attestor);
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));
    }

    function test_adminCannotWithdraw() public {
        address vault = factory.deployVault(X_ID);
        vm.deal(vault, 1 ether);
        _bind(creator, 1);

        vm.prank(admin);
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).claimNative(payable(admin), 1 ether);
    }

    function test_factoryCannotWithdraw() public {
        address vault = factory.deployVault(X_ID);
        vm.deal(vault, 1 ether);
        _bind(creator, 1);

        vm.prank(address(factory));
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));
    }

    function test_strangerCannotWithdraw() public {
        address vault = factory.deployVault(X_ID);
        vm.deal(vault, 1 ether);
        _bind(creator, 1);

        vm.prank(attacker);
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));
    }

    function test_unboundVaultCannotBeDrainedByAnyone() public {
        address vault = factory.deployVault(X_ID);
        vm.deal(vault, 1 ether);

        vm.prank(attacker);
        vm.expectRevert(FeeVault.NoOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));

        vm.prank(attestor);
        vm.expectRevert(FeeVault.NoOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));
    }

    // ==================================================================
    // Attestations
    // ==================================================================

    function test_firstBindIsImmediate() public {
        address vault = _bind(creator, 1);
        assertEq(FeeVault(payable(vault)).owner(), creator);
    }

    function test_wrongSignerRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(rogueKey, X_ID, attacker, deadline, 1);

        vm.expectRevert(FeeVaultFactory.BadAttestation.selector);
        factory.bindOwner(X_ID, attacker, deadline, 1, sig);
    }

    function test_expiredAttestationRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, X_ID, creator, deadline, 1);

        vm.warp(deadline + 1);
        vm.expectRevert(FeeVaultFactory.Expired.selector);
        factory.bindOwner(X_ID, creator, deadline, 1, sig);
    }

    function test_attestationCannotBeReplayed() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, X_ID, creator, deadline, 7);
        factory.bindOwner(X_ID, creator, deadline, 7, sig);

        vm.expectRevert(FeeVaultFactory.AttestationUsed.selector);
        factory.bindOwner(X_ID, creator, deadline, 7, sig);
    }

    /**
     * Signature malleability. Every ECDSA signature has a twin with s flipped
     * to n-s. Without the s-range check in _recover, that twin is a second
     * valid signature for the same attestation, which walks straight past the
     * replay guard above.
     */
    function test_malleableSignatureRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, X_ID, creator, deadline, 9);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 flippedS = bytes32(n - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory twin = abi.encodePacked(r, flippedS, flippedV);

        vm.expectRevert(FeeVaultFactory.BadAttestation.selector);
        factory.bindOwner(X_ID, creator, deadline, 9, twin);
    }

    function test_attestationForOneAccountCannotBindAnother() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, "111", creator, deadline, 1);

        vm.expectRevert(FeeVaultFactory.BadAttestation.selector);
        factory.bindOwner("222", creator, deadline, 1, sig);
    }

    // ==================================================================
    // Rebinding — the window that makes a stolen attestor key survivable.
    // ==================================================================

    function test_rebindIsDelayed() public {
        address vault = _bind(creator, 1);
        _bind(attacker, 2);

        // Still the real creator, immediately after the attacker's bind.
        assertEq(FeeVault(payable(vault)).owner(), creator);
        assertEq(FeeVault(payable(vault)).pendingOwner(), attacker);
    }

    function test_rebindCannotBeFinalisedEarly() public {
        address vault = _bind(creator, 1);
        _bind(attacker, 2);

        vm.warp(block.timestamp + 47 hours);
        vm.expectRevert(FeeVault.TooEarly.selector);
        FeeVault(payable(vault)).finaliseOwnerChange();
    }

    function test_ownerCanCancelHostileRebind() public {
        address vault = _bind(creator, 1);
        vm.deal(vault, 3 ether);

        // Attestor key is stolen and used to point the vault at an attacker.
        _bind(attacker, 2);

        // The real owner notices within the window and kills it.
        vm.prank(creator);
        FeeVault(payable(vault)).cancelOwnerChange();

        vm.warp(block.timestamp + 100 hours);
        vm.expectRevert(FeeVault.NothingPending.selector);
        FeeVault(payable(vault)).finaliseOwnerChange();

        assertEq(FeeVault(payable(vault)).owner(), creator);

        vm.prank(creator);
        FeeVault(payable(vault)).sweep(address(0));
        assertEq(creator.balance, 3 ether, "funds should still be the creator's");
    }

    function test_attackerCannotCancelTheirOwnRebind() public {
        address vault = _bind(creator, 1);
        _bind(attacker, 2);

        vm.prank(attacker);
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).cancelOwnerChange();
    }

    function test_legitimateRebindWorksAfterDelay() public {
        address vault = _bind(creator, 1);
        address newWallet = address(0xBEEF1);
        _bind(newWallet, 2);

        vm.warp(block.timestamp + 48 hours);
        FeeVault(payable(vault)).finaliseOwnerChange();

        assertEq(FeeVault(payable(vault)).owner(), newWallet);
        assertEq(FeeVault(payable(vault)).pendingOwner(), address(0));
    }

    // ==================================================================
    // Claiming
    // ==================================================================

    function test_claimToken() public {
        address vault = _bind(creator, 1);
        MockToken token = new MockToken();
        token.mint(vault, 1000);

        vm.prank(creator);
        FeeVault(payable(vault)).claimToken(address(token), creator, 400);

        assertEq(token.balanceOf(creator), 400);
        assertEq(token.balanceOf(vault), 600);
    }

    function test_sweepHandlesTokensThatReturnNothing() public {
        address vault = _bind(creator, 1);
        NoReturnToken token = new NoReturnToken();
        token.mint(vault, 500);

        vm.prank(creator);
        FeeVault(payable(vault)).sweep(address(token));

        assertEq(token.balanceOf(creator), 500, "non-standard token should still sweep");
    }

    function test_claimToZeroAddressReverts() public {
        address vault = _bind(creator, 1);
        vm.deal(vault, 1 ether);

        vm.prank(creator);
        vm.expectRevert(FeeVault.ZeroAddress.selector);
        FeeVault(payable(vault)).claimNative(payable(address(0)), 1 ether);
    }

    // ==================================================================
    // Admin
    // ==================================================================

    function test_onlyAdminRotatesAttestor() public {
        vm.prank(attacker);
        vm.expectRevert(FeeVaultFactory.NotAdmin.selector);
        factory.rotateAttestor(attacker);

        vm.prank(admin);
        factory.rotateAttestor(address(0xFEED));
        assertEq(factory.attestor(), address(0xFEED));
    }

    function test_oldAttestorStopsWorkingAfterRotation() public {
        vm.prank(admin);
        factory.rotateAttestor(address(0xFEED));

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(attestorKey, X_ID, attacker, deadline, 1);

        vm.expectRevert(FeeVaultFactory.BadAttestation.selector);
        factory.bindOwner(X_ID, attacker, deadline, 1, sig);
    }

    // ==================================================================
    // Fuzz
    // ==================================================================

    function testFuzz_predictionAlwaysMatchesDeployment(string calldata xUserId) public {
        vm.assume(bytes(xUserId).length > 0 && bytes(xUserId).length < 64);
        assertEq(factory.deployVault(xUserId), factory.predictVault(xUserId));
    }

    function testFuzz_onlyOwnerEverWithdraws(address caller) public {
        address vault = _bind(creator, 1);
        vm.deal(vault, 1 ether);
        vm.assume(caller != creator);

        vm.prank(caller);
        vm.expectRevert(FeeVault.NotOwner.selector);
        FeeVault(payable(vault)).sweep(address(0));
    }
}

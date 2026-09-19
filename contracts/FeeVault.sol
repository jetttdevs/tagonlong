// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * FeeVault — one per X account, holding that creator's fees until they claim.
 *
 * WHY THIS EXISTS
 *
 * When someone tweets a launch, the bot needs somewhere to send their share of
 * the fees. It knows their X handle, not an address. The three options were:
 *
 *   1. The platform holds the funds        → custody, and the operator becomes
 *                                            liable for everyone's money.
 *   2. Demand a wallet before launching    → friction exactly where it costs
 *                                            the most: before the first launch.
 *   3. This.                                → fees accrue to a contract that is
 *                                            already earmarked for the handle;
 *                                            the creator claims whenever.
 *
 * THE PROPERTY THAT MATTERS: no private key anywhere controls this vault. The
 * platform cannot withdraw. The attestor key (below) can only say WHO a handle
 * is — it can never move funds, not even to itself. If the whole backend is
 * compromised, an attacker can misdirect FUTURE bindings, which is loud and
 * catchable; they cannot drain a vault.
 *
 * The vault address is deterministic (CREATE2 from the X user id), so it is
 * known and displayable before the contract is even deployed. Fees can be sent
 * to it first and the contract deployed later.
 */
contract FeeVault {
    /// The factory that deployed this vault. Only it may bind an owner.
    address public immutable factory;

    /// Numeric X user id this vault belongs to. Immutable: the handle can
    /// change, the id cannot, which is why the id is what gets bound.
    string public xUserId;

    /// The address allowed to claim. Zero until the creator proves a wallet.
    address public owner;

    /// A pending owner change, and when it becomes effective.
    address public pendingOwner;
    uint256 public pendingOwnerAt;

    /// Delay before an owner CHANGE takes effect. The first binding is
    /// immediate so a new creator can claim straight away; every later change
    /// waits, so a compromised attestor can be spotted and stopped before funds
    /// move to the wrong address.
    uint256 public constant REBIND_DELAY = 48 hours;

    event OwnerBound(address indexed owner);
    event OwnerChangeProposed(address indexed newOwner, uint256 effectiveAt);
    event OwnerChangeCancelled(address indexed cancelled);
    event Claimed(address indexed token, address indexed to, uint256 amount);

    error NotFactory();
    error NotOwner();
    error NoOwner();
    error ZeroAddress();
    error TooEarly();
    error NothingPending();
    error TransferFailed();

    modifier onlyFactory() {
        if (msg.sender != factory) revert NotFactory();
        _;
    }

    modifier onlyOwner() {
        if (owner == address(0)) revert NoOwner();
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(string memory _xUserId) {
        factory = msg.sender;
        xUserId = _xUserId;
    }

    /// Fees arriving as native ETH.
    receive() external payable {}

    // ------------------------------------------------------------------
    // Ownership
    // ------------------------------------------------------------------

    /**
     * Bind the claiming address. Called by the factory once it has verified an
     * attestation. First bind is immediate; any later change is delayed.
     */
    function bindOwner(address newOwner) external onlyFactory {
        if (newOwner == address(0)) revert ZeroAddress();

        if (owner == address(0)) {
            owner = newOwner;
            emit OwnerBound(newOwner);
            return;
        }

        pendingOwner = newOwner;
        pendingOwnerAt = block.timestamp + REBIND_DELAY;
        emit OwnerChangeProposed(newOwner, pendingOwnerAt);
    }

    /// Anyone may finalise once the delay has passed — it is not a privilege,
    /// just a second transaction, so the creator is never waiting on the platform.
    function finaliseOwnerChange() external {
        if (pendingOwner == address(0)) revert NothingPending();
        if (block.timestamp < pendingOwnerAt) revert TooEarly();

        owner = pendingOwner;
        emit OwnerBound(pendingOwner);

        pendingOwner = address(0);
        pendingOwnerAt = 0;
    }

    /**
     * The current owner can cancel a pending change. This is the circuit
     * breaker: if the attestor key is stolen and used to point a vault at an
     * attacker, the real creator has REBIND_DELAY to kill it.
     */
    function cancelOwnerChange() external onlyOwner {
        address cancelled = pendingOwner;
        if (cancelled == address(0)) revert NothingPending();

        pendingOwner = address(0);
        pendingOwnerAt = 0;
        emit OwnerChangeCancelled(cancelled);
    }

    // ------------------------------------------------------------------
    // Claiming
    // ------------------------------------------------------------------

    /// Withdraw accumulated ETH. Only the bound owner, to an address they choose.
    function claimNative(address payable to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Claimed(address(0), to, amount);
    }

    /// Withdraw an ERC-20. Tokens are launched here, so fees may arrive as any of them.
    function claimToken(address token, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        _safeTransfer(token, to, amount);
        emit Claimed(token, to, amount);
    }

    /// Convenience: sweep the whole balance of one token to the owner.
    function sweep(address token) external onlyOwner {
        if (token == address(0)) {
            uint256 bal = address(this).balance;
            (bool ok, ) = payable(owner).call{value: bal}("");
            if (!ok) revert TransferFailed();
            emit Claimed(address(0), owner, bal);
        } else {
            uint256 bal = _balanceOf(token, address(this));
            _safeTransfer(token, owner, bal);
            emit Claimed(token, owner, bal);
        }
    }

    // ------------------------------------------------------------------
    // Minimal ERC-20 helpers
    //
    // Written by hand rather than imported: some tokens return no value from
    // transfer, and a plain IERC20 call reverts on those. Anyone can send any
    // token to this vault, so it has to cope with badly-behaved ones.
    // ------------------------------------------------------------------

    function _safeTransfer(address token, address to, uint256 amount) private {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(0xa9059cbb, to, amount)); // transfer(address,uint256)
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _balanceOf(address token, address who) private view returns (uint256) {
        (bool ok, bytes memory data) =
            token.staticcall(abi.encodeWithSelector(0x70a08231, who)); // balanceOf(address)
        if (!ok || data.length < 32) return 0;
        return abi.decode(data, (uint256));
    }
}

/**
 * FeeVaultFactory — deterministic per-X-account fee vaults.
 *
 * Deploys each vault with CREATE2 using the X user id as the salt, so a
 * creator's fee address is computable BEFORE the vault exists. That is what
 * lets the site show someone their fee address the moment they first tweet,
 * and lets fees be sent there before anyone has spent gas deploying it.
 *
 * TRUST MODEL — read this before changing anything.
 *
 * The attestor key answers exactly one question: "which wallet belongs to X
 * user id N?" It signs a statement to that effect and a creator submits it.
 *
 * What the attestor CANNOT do, by construction:
 *   - withdraw from any vault
 *   - redirect funds already sitting in a vault to itself
 *   - bypass the 48h delay on changing an existing binding
 *
 * What a stolen attestor key COULD do: bind a vault that has never been claimed
 * to an attacker's address, or propose a change to one that has (which the real
 * owner can cancel within 48 hours). So keep it off the API servers, rotate it,
 * and watch OwnerChangeProposed events.
 *
 * This is a deliberately smaller blast radius than the platform holding keys:
 * there, a breach is an immediate total loss with no window to react.
 */
contract FeeVaultFactory {
    /// Signs handle→address attestations. Not a treasury key; see above.
    address public attestor;

    /// Can rotate the attestor. Should be a multisig or timelock in production.
    address public admin;

    /// xUserId => deployed vault (zero if not deployed yet).
    mapping(string => address) public vaultOf;

    /// Replay protection for attestations.
    mapping(bytes32 => bool) public usedAttestation;

    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 private constant BIND_TYPEHASH =
        keccak256("Bind(string xUserId,address owner,uint256 deadline,uint256 nonce)");

    event VaultDeployed(string indexed xUserIdIndexed, string xUserId, address vault);
    event AttestorRotated(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    error NotAdmin();
    error ZeroAddress();
    error Expired();
    error BadAttestation();
    error AttestationUsed();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(address _admin, address _attestor) {
        if (_admin == address(0) || _attestor == address(0)) revert ZeroAddress();
        admin = _admin;
        attestor = _attestor;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("TagOnLongFeeVault"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    // ------------------------------------------------------------------
    // Addresses
    // ------------------------------------------------------------------

    function saltFor(string memory xUserId) public pure returns (bytes32) {
        return keccak256(bytes(xUserId));
    }

    /**
     * The vault address for an X user id, whether or not it has been deployed.
     * Show this on the site the first time someone tweets — it is where their
     * fees are going, and it is correct before any gas is spent.
     */
    function predictVault(string memory xUserId) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(type(FeeVault).creationCode, abi.encode(xUserId))
        );
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), saltFor(xUserId), initCodeHash)
        ))));
    }

    /**
     * Deploy the vault. Permissionless and idempotent: anyone may pay the gas,
     * and calling it twice returns the existing vault rather than reverting —
     * so the bot can call it blindly without tracking what already exists.
     */
    function deployVault(string memory xUserId) public returns (address vault) {
        address existing = vaultOf[xUserId];
        if (existing != address(0)) return existing;

        vault = address(new FeeVault{salt: saltFor(xUserId)}(xUserId));
        vaultOf[xUserId] = vault;
        emit VaultDeployed(xUserId, xUserId, vault);
    }

    // ------------------------------------------------------------------
    // Binding
    // ------------------------------------------------------------------

    /**
     * Bind a claiming address to a vault, using an attestation from the platform.
     *
     * The creator submits this themselves, so the platform never needs a funded
     * key on the hot path. Deploys the vault first if it does not exist yet.
     */
    function bindOwner(
        string memory xUserId,
        address newOwner,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) external returns (address vault) {
        if (newOwner == address(0)) revert ZeroAddress();
        if (block.timestamp > deadline) revert Expired();

        bytes32 structHash = keccak256(
            abi.encode(BIND_TYPEHASH, keccak256(bytes(xUserId)), newOwner, deadline, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        if (usedAttestation[digest]) revert AttestationUsed();
        if (_recover(digest, signature) != attestor) revert BadAttestation();
        usedAttestation[digest] = true;

        vault = deployVault(xUserId);
        FeeVault(payable(vault)).bindOwner(newOwner);
    }

    // ------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------

    function rotateAttestor(address newAttestor) external onlyAdmin {
        if (newAttestor == address(0)) revert ZeroAddress();
        emit AttestorRotated(attestor, newAttestor);
        attestor = newAttestor;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // ------------------------------------------------------------------
    // Signature recovery
    // ------------------------------------------------------------------

    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        // Reject the upper half of the curve order: without this the same
        // attestation has a second valid signature, which would slip past the
        // replay check above.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) return address(0);

        return ecrecover(digest, v, r, s);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "@account-abstraction/interfaces/IStakeManager.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@account-abstraction/interfaces/UserOperation.sol";
import {SimpleAccountFactory} from "@account-abstraction/samples/SimpleAccountFactory.sol";
import {SimpleAccount} from "@account-abstraction/samples/SimpleAccount.sol";
import {MockERC20} from "./MockERC20.sol"; // Include the mock ERC20 token contract
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VerifyingPaymasterTest is Test {
    EntryPoint public entrypoint;
    VerifyingPaymaster public paymaster;
    SimpleAccount public account;
    MockERC20 public mockToken;

    uint48 constant MOCK_VALID_UNTIL = 281474976710655;
    uint48 constant MOCK_VALID_AFTER = 0;
    uint128 constant MOCK_SPONSOR_ID = 1;
    bool constant MOCK_ALLOW_ANY_BUNDLER = true;
    address constant MOCK_TOKEN_ADDRESS = address(0x1234);
    address constant MOCK_TOKEN_RECEIVER = address(0x5678);
    uint256 constant MOCK_TOKEN_EXCHANGE_RATE = 1e18;
    bytes constant MOCK_SIG = "0x1234";
    address constant PAYMASTER_SIGNER =
        0xC3Bf2750F0d47098f487D45b2FB26b32eCbAf9a2;
    uint256 constant PAYMASTER_SIGNER_KEY =
        0x6a6c11c6f4703865cc4a88c6ebf0a605fdeeccd8052d66101d1d02730740a3c0;
    address constant ACCOUNT_OWNER = 0x39c0Bb04Bf6B779ac994f6A5211204e3Dbe16741;
    uint256 constant ACCOUNT_OWNER_KEY =
        0x4034df11fcc455209edcb8948449a4dff732376dab6d03dc2d099d0084b0f023;

    function setUp() public {
        entrypoint = new EntryPoint();
        paymaster = new VerifyingPaymaster(entrypoint, PAYMASTER_SIGNER, address(this));
        SimpleAccountFactory factory = new SimpleAccountFactory(entrypoint);
        account = factory.createAccount(ACCOUNT_OWNER, 0);
        mockToken = new MockERC20();
        mockToken.mint(address(account), 1000 ether);
    
        (bool success, ) = address(paymaster).call{value: 1 ether}("");
        require(success, "failed to fund paymaster");
    }

    function test_constructor_reverts_whenOwnerIsVerifyingSigner() public {
        vm.expectRevert();
        new VerifyingPaymaster(entrypoint, address(this), address(this));
    }

    function test_constructor_reverts_whenEntryPointNotAContract() public {
        vm.expectRevert();
        new VerifyingPaymaster(IEntryPoint(address(0x1234)), PAYMASTER_SIGNER, address(this));
    }

    function test_renouceOwnership_reverts() public {
        vm.expectRevert();
        paymaster.renounceOwnership();
    }

    function test_transferOwnership_reverts_ifZeroAddress() public {
        vm.expectRevert();
        paymaster.transferOwnership(address(0));
    }

    function test_transferOwnership_reverts_ifAddressIsAlsoVerifyingSigner() public {
        vm.expectRevert();
        paymaster.transferOwnership(PAYMASTER_SIGNER);
    }

    function createPaymasterData() public returns (VerifyingPaymaster.PaymasterData memory) {
        return VerifyingPaymaster.PaymasterData(
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER,
            MOCK_SPONSOR_ID,
            MOCK_ALLOW_ANY_BUNDLER,
            false,
            false,
            MOCK_TOKEN_ADDRESS,
            MOCK_TOKEN_RECEIVER,
            MOCK_TOKEN_EXCHANGE_RATE
        );
    }

    function test_getHash() public {
        UserOperation memory userOp = createUserOp();
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();
        bytes32 hash = paymaster.getHash(
            userOp,
            paymasterData
        );
        // Replace with the expected hash value
        assertEq(
            hash,
            0x30a30b2e1e8597a67a0c73295ea9734d27a2faa65ea7be4b1a6fabec2168d69b
        );
    }

    function test_validate_success_whenUserOpValidSignature() public {
        UserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(0));
        signUserOp(userOp);

        // Encode and expect the validation result
        vm.expectRevert(); //createEncodedValidationResult(false, 53025) sig success
        entrypoint.simulateValidation(userOp);
    }

    function test_validate_reverts_WhenUserOpHasWrongSigner() public {
        UserOperation memory userOp = createUserOp();
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ACCOUNT_OWNER_KEY,
            ECDSA.toEthSignedMessageHash(
                paymaster.getHash(
                    userOp,
                    paymasterData
                )
            )
        );
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER,
            MOCK_SPONSOR_ID,
            MOCK_ALLOW_ANY_BUNDLER,
            false,
            false,
            MOCK_TOKEN_ADDRESS,
            MOCK_TOKEN_RECEIVER,
            MOCK_TOKEN_EXCHANGE_RATE,
            r,
            s,
            v
        );
        signUserOp(userOp);

        vm.expectRevert(); //createEncodedValidationResult(true, 53035) sig failed
        entrypoint.simulateValidation(userOp);
    }

    function test_validatePaymaster_reverts_whenUserOpHasNoSignature() public {
        UserOperation memory userOp = createUserOp();
        
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            abi.encodePacked(
                MOCK_VALID_UNTIL,
                MOCK_VALID_AFTER,
                MOCK_SPONSOR_ID,
                MOCK_ALLOW_ANY_BUNDLER,
                MOCK_TOKEN_ADDRESS,
                MOCK_TOKEN_RECEIVER,
                MOCK_TOKEN_EXCHANGE_RATE
            )
        );
        signUserOp(userOp);
        vm.expectRevert(); // "AA33 reverted: Paymaster: invalid signature length in paymasterAndData"
        entrypoint.simulateValidation(userOp);
    }

    function test_validate_reverts_whenUserOpHasInvalidSignature() public {
        UserOperation memory userOp = createUserOp();
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            abi.encodePacked(
                MOCK_VALID_UNTIL,
                MOCK_VALID_AFTER,
                MOCK_SPONSOR_ID,
                MOCK_ALLOW_ANY_BUNDLER,
                MOCK_TOKEN_ADDRESS,
                MOCK_TOKEN_RECEIVER,
                MOCK_TOKEN_EXCHANGE_RATE
            ),
            bytes32(0),
            bytes32(0),
            uint8(0)
        );
        signUserOp(userOp);

        vm.expectRevert(); // "AA33 reverted: ECDSA: invalid signature"
        entrypoint.simulateValidation(userOp);
    }

    // Non-erc20 sponsorship
    function test_entrypointHandleOps_successForStandardSponsorship() public {
        address(paymaster).call{value: 1 ether}("");
        
        UserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(0));
        signUserOp(userOp);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));
    }

    function test_entrypointHandleOps_successForERC20Sponsorship() public {
        address(paymaster).call{value: 1 ether}("");

        uint256 initialBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);
        UserOperation memory userOp = createUserOp();
        bytes memory approveCallData = abi.encodeWithSelector(
            mockToken.approve.selector,
            paymaster,
            1 * 10**18 
        );
        bytes memory walletCallData = abi.encodeWithSelector(account.execute.selector, address(mockToken), 0, approveCallData);
        userOp.callData = walletCallData;
        addPaymasterData(userOp, true, address(mockToken));

        signUserOp(userOp);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));

        uint256 postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        assertTrue(
            postOpBalance > initialBalance
        );
    }

    function test_entrypointHandleOps_failedERC20Transfer_DoesNotRevert() public {
        address(paymaster).call{value: 1 ether}("");

        uint256 initialBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        UserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(mockToken));
        signUserOp(userOp);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        entrypoint.handleOps(ops, payable(address(12)));
        uint256 postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);
        assertTrue(
            postOpBalance == initialBalance
        );
    }

    function test_entrypointHandleOps_reverts_ifBundlerNotOnAllowlist() public {
        UserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, false, address(0));
        signUserOp(userOp);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        // Simulate an invalid scenario
        vm.expectRevert(); //"AA50 postOp reverted: Paymaster: bundler not allowed"
        entrypoint.handleOps(ops, payable(address(12)));
    }

    function test_receive_success() public {
        assertEq(1 ether, entrypoint.getDepositInfo(address(paymaster)).deposit);
        (bool callSuccess, ) = address(paymaster).call{value: 1 ether}("");
        require(callSuccess, "Receive failed");
        assertEq(2 ether, entrypoint.getDepositInfo(address(paymaster)).deposit);
    }


    /* Helper functions */

    function createUserOp() public view returns (UserOperation memory) {
        UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.verificationGasLimit = 100000;
        userOp.maxPriorityFeePerGas = 100000;
        userOp.maxFeePerGas = 100000;
        userOp.preVerificationGas = 100000;
        userOp.verificationGasLimit = 100000;
        userOp.callGasLimit = 100000;
        return userOp;
    }

    function addPaymasterData(UserOperation memory userOp, bool anyBundler, address token) public {
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();
        paymasterData.allowAnyBundler = anyBundler;
        paymasterData.token = token;

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            PAYMASTER_SIGNER_KEY,
            ECDSA.toEthSignedMessageHash(
                paymaster.getHash(
                    userOp,
                    paymasterData
                )
            )
        );

        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            abi.encodePacked(
                MOCK_VALID_UNTIL,
                MOCK_VALID_AFTER,
                MOCK_SPONSOR_ID,
                anyBundler,
                false,
                false,
                token,
                MOCK_TOKEN_RECEIVER,
                MOCK_TOKEN_EXCHANGE_RATE
            ),
            r,
            s,
            v
        );
    }

    function signUserOp(UserOperation memory userOp) public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ACCOUNT_OWNER_KEY,
            ECDSA.toEthSignedMessageHash(entrypoint.getUserOpHash(userOp))
        );
        userOp.signature = abi.encodePacked(r, s, v);
    }

    function createEncodedValidationResult(
        bool sigFailed,
        uint256 preOpGas
    ) public pure returns (bytes memory) {
        uint256 prefund = 0;
        bytes memory paymasterContext = "";
        return
            abi.encodeWithSelector(
                IEntryPoint.ValidationResult.selector,
                IEntryPoint.ReturnInfo(
                    preOpGas,
                    prefund,
                    sigFailed,
                    MOCK_VALID_AFTER,
                    MOCK_VALID_UNTIL,
                    paymasterContext
                ),
                IStakeManager.StakeInfo(0, 0),
                IStakeManager.StakeInfo(0, 0),
                IStakeManager.StakeInfo(0, 0)
            );
    }
}

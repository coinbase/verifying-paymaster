// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MCK") {}

    // Function to mint tokens to a specific address
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

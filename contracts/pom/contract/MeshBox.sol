// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract GLDToken is Ownable,ERC20 {
    constructor() ERC20("MeshBox", "MESH") {
    }
    function mint(address account, uint256 amount) onlyOwner public{
           _mint(account,amount);
    }
    function burn(address account, uint256 amount) onlyOwner public{
           _burn(account,amount);
    }
}
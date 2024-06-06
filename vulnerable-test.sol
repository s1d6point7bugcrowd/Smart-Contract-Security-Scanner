// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;

    // Constructor
    constructor() {
        owner = msg.sender;
    }

    // Function to deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Function to withdraw Ether from the contract
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // Vulnerable to reentrancy attack
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // Function to transfer balance to another address
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // Function to set a hardcoded address
    function setHardcodedAddress() public {
        owner = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2; // Hardcoded address with correct checksum
    }

    // Function using block.timestamp for randomness
    function getRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    // Function using tx.origin
    function onlyOwner() public view {
        require(tx.origin == owner, "Not the owner");
        // Some owner-only functionality
    }

    // Function with low-level call
    function lowLevelCall(address target, bytes memory data) public {
        (bool success, ) = target.call(data);
        require(success, "Low-level call failed");
    }

    // Unchecked low-level call
    function uncheckedLowLevelCall(address target, bytes memory data) public {
        target.call(data);
    }

    // Function without function modifiers
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    // Function with implicit type conversion
    function implicitConversion() public {
        uint8 smallNumber = 255;
        uint256 bigNumber = smallNumber; // Implicit type conversion
    }
}

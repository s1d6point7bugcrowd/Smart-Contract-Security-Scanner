// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Constructor
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
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

    // Function vulnerable to overflow
    function overflow() public {
        uint256 max = 2**256 - 1;
        totalSupply += max; // Overflow vulnerability
    }

    // Function vulnerable to underflow
    function underflow() public {
        uint256 min = 0;
        totalSupply -= min + 1; // Underflow vulnerability
    }

    // Function vulnerable to integer division error
    function divisionError(uint256 amount) public view returns (uint256) {
        require(amount > 0, "Amount must be greater than zero");
        return totalSupply / amount; // Division error vulnerability
    }

    // Function with unrestricted access to selfdestruct
    function selfDestructContract() public {
        selfdestruct(payable(owner));
    }

    // Function that uses block.number for randomness
    function getAnotherRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.number, block.timestamp)));
    }

    // Function vulnerable to flash loan exploit
    function flashLoanExploit(uint256 amount) public {
        require(amount <= totalSupply, "Amount exceeds total supply");
        balances[msg.sender] += amount;
        totalSupply -= amount;
        // Some operation that should be atomic
        totalSupply += amount;
        balances[msg.sender] -= amount;
    }

    // Function to lock contract operations
    function lockContract() public {
        selfdestruct(payable(owner));
    }
}

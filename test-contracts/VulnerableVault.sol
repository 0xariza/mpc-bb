// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableVault
 * @notice Example contract with intentional vulnerabilities for testing
 * @dev DO NOT USE IN PRODUCTION
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABILITY: Reentrancy - state updated after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State update AFTER external call
    }
    
    // VULNERABILITY: tx.origin for authentication
    function withdrawAll() external {
        require(tx.origin == owner, "Not owner"); // Should use msg.sender
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // VULNERABILITY: No access control
    function setOwner(address newOwner) external {
        owner = newOwner; // Anyone can call this!
    }
}

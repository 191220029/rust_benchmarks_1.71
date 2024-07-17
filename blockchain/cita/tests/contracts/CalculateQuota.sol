pragma solidity ^0.4.24;

import "./Called.sol";

contract CalculateQuota {
    address public calledAddr;
    uint public storedData;

    constructor() public {
        calledAddr = new Called();
    }

    function withoutCall(uint x) public returns (bool) {
        for (uint i = 1; i < x; i++) {
            storedData = i;
        }
        return true;
    }

    function withoutCall() public {
        storedData = 1;
        storedData = 2;
    }

    function withCall(uint x) public {
        Called called = Called(calledAddr);
        called.set(x);
    }

    function withCall() public {
        Called called = Called(calledAddr);
        called.setMulStorage();
    }
}

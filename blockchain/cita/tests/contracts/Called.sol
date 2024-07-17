pragma solidity ^0.4.24;

contract Called {
    uint public storedData;

    function set(uint x) public {
        for (uint i = 1; i < x; i++) {
            storedData = i;
        }
    }

    function setMulStorage() public {
        storedData = 1;
        storedData = 2;
    }

    function setMem(uint x) public pure {
        uint mem;
        for (uint i = 0; i < x; i++) {
            mem = i;
        }
    }
}

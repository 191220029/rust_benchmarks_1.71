pragma solidity ^0.4.24;

import "./SimpleStorage.sol";

contract Factory {
    address public simpleAddress;

    function newSimple() public {
        simpleAddress = new SimpleStorage();
    }

    function callSimple(uint x) public {
        SimpleStorage simple = SimpleStorage(simpleAddress);
        simple.set(x);
    }
}

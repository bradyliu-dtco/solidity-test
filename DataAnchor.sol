pragma solidity ^0.5.0;

import "../ownership/Ownable.sol";

contract DataAnchor is Ownable {

    struct data_info {
        uint256 _type;
        string hash_type;
        bytes hash;
        bytes content;
        uint256 time;
    }
    
    mapping(address => data_info[]) public datas;  //owner => data_info[]
    mapping(address => mapping(bytes32 => bool)) public hashMap;  //owner => (bytes32(hash) => bool)

    event AnchorAdded(address indexed sender, uint256 idx);

    constructor() public {
    }


    // This function adds an anchor to the blockchain. It takes in four parameters: an unsigned integer for the type of anchor, a string for the type of hash, a byte array for the hash, and another byte array for content. The function requires that the length of both the hash_type and hash parameters are greater than 0, otherwise it will throw an error. 
    /**
    * @dev Adds an anchor to the blockchain. 
    * @param _type uint256 - The type of anchor. 
    * @param _hash_type string - The type of hash. 
    * @param _hash bytes - The hash value. 
    * @param _content bytes - The content associated with the anchor. 
    */
    function addAnchor(uint256 _type, string memory _hash_type, bytes memory _hash, bytes memory _content) public {
        require(bytes(_hash_type).length > 0, "hash_type is empty");
        require(bytes(_hash).length > 0, "hash is empty");

        _addAnchor(msg.sender, _type, _hash_type, _hash, _content);
    }

    // This function adds an anchor to the blockchain. It takes in parameters such as the type of anchor, the hash type, the hash, the content, and signature information (signature V value, signature R value, and signature S value). It then requires that the hash type and hash are not empty strings. It calculates a message hash to sign using the provided hash and content. Finally, it uses ecrecover to get the signer's address from the message hash and signature information. Then it calls _addAnchor with all of these parameters to add an anchor to the blockchain.
    /**
    * @dev Adds an anchor to the blockchain 
    * @param _type The type of anchor 
    * @param _hash_type The type of hash used 
    * @param _hash The actual hash 
    * @param _content The content associated with this anchor 
    * @param _sigV Signature V value 
    * @param _sigR Signature R value 
    * @param _sigS Signature S value 
    */
    function addAnchorSigned(uint256 _type, string memory _hash_type, bytes memory _hash, bytes memory _content, uint8 _sigV, bytes32 _sigR, bytes32 _sigS) public onlyOwner {
        require(bytes(_hash_type).length > 0, "hash_type is empty");
        require(bytes(_hash).length > 0, "hash is empty");

        bytes32 _hash256= getMessageHashToSign(_hash, _content);
        address _signer = ecrecover(_hash256, _sigV, _sigR, _sigS);

        _addAnchor(_signer, _type, _hash_type, _hash, _content);        
    }

    function _addAnchor(address _signer, uint256 _type, string memory _hash_type, bytes memory _hash, bytes memory _content) internal {
        bytes32 _hkey= getHashKey(_hash);
        require(hashMap[_signer][_hkey]==false, "hash has existed");

        data_info memory di;
        di._type= _type;
        di.hash_type= _hash_type;
        di.hash= _hash;
        di.content= _content;
        di.time= now;

        datas[_signer].push(di);
        hashMap[_signer][_hkey]= true;

        emit AnchorAdded(_signer, datas[_signer].length-1);
    }

    // This function returns the number of anchors associated with a given address. 
    /** 
    * @dev Returns the number of anchors associated with a given address. 
    * @param _owner The address to check for anchors. 
    * @return uint256 The number of anchors associated with the given address. 
    */
    function getAnchorCount(address _owner) public view returns (uint256) {
		return datas[_owner].length;
	}

    // This function is used to get the anchor information from a given address and index. The function takes in an address and an index as parameters, and returns a tuple containing the anchor type, hash type, hash, content, and time. 
    /** 
    * @dev Returns the anchor information from a given address and index. 
    * @param _owner Address of the owner of the data. 
    * @param _idx Index of the data in the array. 
    * @return A tuple containing the anchor type, hash type, hash, content, and time. 
    */
    function getAnchor(address _owner, uint256 _idx) public view returns (uint256, string memory, bytes memory, bytes memory, uint256) {
		if(datas[_owner].length <= _idx) return (0, "", "", "", 0);

        data_info storage di= datas[_owner][_idx];
        return (di._type, di.hash_type, di.hash, di.content, di.time);
	}

    function getHashKey(bytes memory _hash) public pure returns (bytes32) {
        return keccak256(_hash);
    }

    function anchorHasExisted(address _owner, bytes memory _hash) public view returns (bool) {
        return hashMap[_owner][getHashKey(_hash)];
	}

    function getMessageHashToSign(bytes memory _hash, bytes memory _content) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), _hash, _content));
    }

}
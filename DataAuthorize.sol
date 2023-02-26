pragma solidity ^0.5.0;

import "../ownership/Ownable.sol";
import "./IDataAnchor.sol";

contract DataAuthorize is Ownable {

    struct auth_record {
        address dataSource;
        bytes hash;
        address owner;
        address recipient;
        string comment;
        uint256 time;
        uint256 validity;
    }
    
    auth_record[] public auths;

    mapping(address => uint256[]) public authsOwners;  //owner => uint256[]
    mapping(address => uint256[]) public authsRecipients;  //recipient => uint256[]
    mapping(address => mapping(bytes32 => uint256[])) public authsHashOwners;  //owner => (hkey => uint256[])
    mapping(bytes32 => uint256[]) public uniqueHashAuths;  //ukey(owner, recipient, hash) => uint256[]

    mapping(address => uint256) public nonce;  //owner => nonce, for auth owner signing

    event AuthorizationAdded(address indexed sender, uint256 authIdx, uint256 ownerIdx, uint256 recipientIdx);
    event AuthorizationUpdated(address indexed sender, uint256 authIdx);

    constructor() public {
    }

    modifier dataOwner(address _dataSource, bytes memory _hash) {
    	require(IDataAnchor(_dataSource).dataHasExisted(msg.sender, _hash), "no data to authorize with owner");
    	_;
  	}

    // This function adds an authorization to a data source. It takes in the address of the data source, a byte array representing the hash of the data, the address of the recipient, a string comment, and a uint256 representing the validity of the authorization. The function is limited to only those who are designated as data owners for that particular data source. 
    /**
    * @dev Adds an authorization to a data source. 
    * @param _dataSource The address of the data source. 
    * @param _hash A byte array representing the hash of the data. 
    * @param _recipient The address of the recipient. 
    * @param _comment A string comment. 
    * @param _validity A uint256 representing the validity of the authorization. 
    */
    function addAuthorization(address _dataSource, bytes memory _hash, address _recipient, string memory _comment, uint256 _validity) public dataOwner(_dataSource, _hash) {
        _addAuthorization(_dataSource, msg.sender, _hash, _recipient, _comment, _validity);
    }

    // This function adds an authorization to a data source, given the owner address, hash of the data, recipient address, comment string, validity period and signature parameters. It requires that the data exists with the owner and that the signature is valid. 
    /**
    * @dev Add an authorization to a data source. 
    * @param _dataSource Address of the data source. 
    * @param _owner Address of the owner of the data. 
    * @param _hash Hash of the data to be authorized. 
    * @param _recipient Address of the recipient of the authorization. 
    * @param _comment Comment string associated with this authorization. 
    * @param _validity Validity period for this authorization in seconds. 
    * @param _sigV Signature parameter V (0 or 1). 
    * @param _sigR Signature parameter R (32 bytes).  
    * @param _sigS Signature parameter S (32 bytes).  
    */
    function addAuthorizationSigned(address _dataSource, address _owner, bytes memory _hash, address _recipient, string memory _comment, uint256 _validity, uint8 _sigV, bytes32 _sigR, bytes32 _sigS) public onlyOwner {
        require(IDataAnchor(_dataSource).dataHasExisted(_owner, _hash), "no data to authorize with owner");

        bytes32 _hash256= getAuthorizationMessageHashToSign(_hash, _recipient, nonce[_owner]);
        address _signer = ecrecover(_hash256, _sigV, _sigR, _sigS);
        require(_owner==_signer, "signature error");        

        _addAuthorization(_dataSource, _owner, _hash, _recipient, _comment, _validity);
        nonce[_owner]++;
    }

    function _addAuthorization(address _dataSource, address _owner, bytes memory _hash, address _recipient, string memory _comment, uint256 _validity) internal {
        
        bytes32 _ukey= getUniqueHashKey(_owner, _recipient, _hash);
        require(uniqueHashAuths[_ukey].length==0, "it has authorized");
        bytes32 _hkey= getHashKey(_hash);

        auth_record memory ar;
        ar.dataSource= _dataSource;
        ar.hash= _hash;
        ar.owner= _owner;
        ar.recipient= _recipient;
        ar.comment= _comment;
        ar.time= now;
        ar.validity= _validity;

        auths.push(ar);
        authsOwners[_owner].push(auths.length-1);
        authsRecipients[_recipient].push(auths.length-1);
        authsHashOwners[_owner][_hkey].push(auths.length-1);
        uniqueHashAuths[_ukey].push(auths.length-1);        

        emit AuthorizationAdded(_owner, auths.length-1, authsOwners[_owner].length-1, authsRecipients[_recipient].length-1);
    }

    // This function updates an authorization with the given parameters. It calls the _updateAuthorization() function, passing in the sender of the message, the hash, recipient, comment and validity as parameters.
    /**
    * @dev Updates an authorization with given parameters. 
    * @param _hash Hash of the authorization. 
    * @param _recipient Recipient of the authorization. 
    * @param _comment Comment for the authorization. 
    * @param _validity Validity of the authorization. 
    */
    function updateAuthorization(bytes memory _hash, address _recipient, string memory _comment, uint256 _validity) public {
        _updateAuthorization(msg.sender, _hash, _recipient, _comment, _validity);
    }

    //This function updates an authorization with a signature. It takes in the owner's address, a hash, the recipient's address, a comment, a validity period, and the signature components (signature V value, signature R value, and signature S value). It first checks that the owner is the signer of the message by using ecrecover to compare the owner's address to the signer address. If they match, it updates the authorization with the given parameters and increments the nonce for that owner. 
    /**
    * @dev Updates an authorization with a signature. 
    * @param _owner The owner's address. 
    * @param _hash A hash. 
    * @param _recipient The recipient's address. 
    * @param _comment A comment. 
    * @param _validity The validity period of this authorization. 
    * @param _sigV Signature V value of this authorization. 
    * @param _sigR Signature R value of this authorization. 
    * @param _sigS Signature S value of this authorization.  
    */
    function updateAuthorizationSigned(address _owner, bytes memory _hash, address _recipient, string memory _comment, uint256 _validity, uint8 _sigV, bytes32 _sigR, bytes32 _sigS) public onlyOwner {
        bytes32 _hash256= getAuthorizationMessageHashToSign(_hash, _recipient, nonce[_owner]);
        address _signer = ecrecover(_hash256, _sigV, _sigR, _sigS);
        require(_owner==_signer, "signature error");

        _updateAuthorization(_owner, _hash, _recipient, _comment, _validity);
        nonce[_owner]++;
    }

    function _updateAuthorization(address _owner, bytes memory _hash, address _recipient, string memory _comment, uint256 _validity) internal {
        bytes32 _ukey= getUniqueHashKey(_owner, _recipient, _hash);
        require(uniqueHashAuths[_ukey].length > 0, "no authorized record");

        uint256 _authIdx= uniqueHashAuths[_ukey][0];
        auth_record storage ar= auths[_authIdx];
        require(ar.owner==_owner, "not data owner");
        require(ar.recipient==_recipient, "recipient error");

        ar.comment= _comment;
        ar.validity= _validity;

        emit AuthorizationUpdated(_owner, _authIdx);
    }
   
    // This function revokes an authorization by updating the authorization with the current timestamp. 
    /**
    * @dev Revokes an authorization by updating the authorization with the current timestamp. 
    * @param _hash The hash of the authorization to revoke. 
    * @param _recipient The address of the recipient of the revoked authorization. 
    * @param _comment A comment associated with the revoked authorization. 
    */
    function revokeAuthorization(bytes memory _hash, address _recipient, string memory _comment) public {
        _updateAuthorization(msg.sender, _hash, _recipient, _comment, now);
    }

    // This function revokes an authorization signed by the owner. It takes in the address of the owner, a hash of the authorization, the address of the recipient, a comment about the authorization, and signature data. It then verifies that the owner is indeed the signer of this authorization using ecrecover. If successful, it updates the authorization and increments the nonce for this owner. 
    /**
    * @dev Revokes an authorization signed by _owner with given signature data. 
    * @param _owner Address of owner signing this transaction 
    * @param _hash Hash of authorization to revoke 
    * @param _recipient Address of recipient to revoke authorization from 
    * @param _comment Comment about this revocation 
    * @param _sigV Signature data V value 
    * @param _sigR Signature data R value 
    * @param _sigS Signature data S value  
    */
    function revokeAuthorizationSigned(address _owner, bytes memory _hash, address _recipient, string memory _comment, uint8 _sigV, bytes32 _sigR, bytes32 _sigS) public onlyOwner {
        bytes32 _hash256= getAuthorizationMessageHashToSign(_hash, _recipient, nonce[_owner]);
        address _signer = ecrecover(_hash256, _sigV, _sigR, _sigS);
        require(_owner==_signer, "signature error");

        _updateAuthorization(_owner, _hash, _recipient, _comment, now);
        nonce[_owner]++;
    }

    // This function returns the number of authorizations an owner has. It takes in the address of an owner as an argument and returns a uint256 value. 
    /**
    * @dev Returns the number of authorizations for a given owner address. 
    * @param _owner The address of the owner to query. 
    * @return The number of authorizations for the given owner address. 
    */
    function getAuthorizationCountForOwner(address _owner) public view returns (uint256) {
		return authsOwners[_owner].length;
	}

    // This function returns the authorization data for a given owner and index.
    // @param _owner address of the owner
    // @param _idx index of the authorization record
    // @return (dataSource, hash, owner, recipient, comment, time, validity)
    function getAuthorizationForOwnerByIdx(address _owner, uint256 _idx) public view returns (address, bytes memory, address, address, string memory, uint256, uint256) {
        if(authsOwners[_owner].length <= _idx) return (address(0), "", address(0), address(0), "", 0, 0);

        uint256 _authIdx= authsOwners[_owner][_idx];
        auth_record storage ar= auths[_authIdx];
        return (ar.dataSource, ar.hash, ar.owner, ar.recipient, ar.comment, ar.time, ar.validity);
	}

    // This function returns the number of authorizations a given recipient has. The NatSpec Format comment for this function is:
    /**
    * @dev Returns the number of authorizations a given recipient has. 
    * @param _recipient The address of the recipient to check. 
    * @return The number of authorizations. 
    */
    function getAuthorizationCountForRecipient(address _recipient) public view returns (uint256) {
		return authsRecipients[_recipient].length;
	} 

    // This function retrieves the authorization record for a given recipient and index. It takes in two parameters, an address of the recipient and an index, and returns seven values: address of the data source, bytes memory of the hash, address of the owner, address of the recipient, string memory of the comment, uint256 time and uint256 validity. 
    /**
    * @dev Retrieves the authorization record for a given recipient and index. 
    * @param _recipient Address of the recipient. 
    * @param _idx Index. 
    * @return Address of the data source, bytes memory of the hash, address of the owner, address of the recipient, string memory of the comment, uint256 time and uint256 validity. 
    */
    function getAuthorizationForRecipientByIdx(address _recipient, uint256 _idx) public view returns (address, bytes memory, address, address, string memory, uint256, uint256) {
        if(authsRecipients[_recipient].length <= _idx) return (address(0), "", address(0), address(0), "", 0, 0);

        uint256 _authIdx= authsRecipients[_recipient][_idx];
        auth_record storage ar= auths[_authIdx];
        return (ar.dataSource, ar.hash, ar.owner, ar.recipient, ar.comment, ar.time, ar.validity);
	}

    // This function returns the number of authorizations for an owner with a given hash. The NatSpec Format comment for this function is: 
    /**
    * @dev Returns the number of authorizations for an owner with a given hash.
    * @param _owner The address of the owner.
    * @param _hash The hash to check.
    * @return The number of authorizations. 
    */
    function getAuthorizationCountForOwnerWithHash(address _owner, bytes memory _hash) public view returns (uint256) {
		return authsHashOwners[_owner][getHashKey(_hash)].length;
	}

    // This function gets the authorization for an owner with a given hash and index. It takes in an address, a bytes memory, and a uint256 as parameters. It returns an address, bytes memory, two addresses, a string memory, and two uint256s. 
    /**
    * @dev Gets the authorization for an owner with a given hash and index. 
    * @param _owner The address of the owner. 
    * @param _hash The bytes memory of the hash. 
    * @param _idx The uint256 index of the authorization record. 
    * @return An address, bytes memory, two addresses, a string memory, and two uint256s representing the dataSource, hash, owner, recipient, comment, time and validity respectively. 
    */
    function getAuthorizationForOwnerWithHashByIdx(address _owner, bytes memory _hash, uint256 _idx) public view returns (address, bytes memory, address, address, string memory, uint256, uint256) {
        bytes32 _hkey= getHashKey(_hash);
        if(authsHashOwners[_owner][_hkey].length <= _idx) return (address(0), "", address(0), address(0), "", 0, 0);

        uint256 _authIdx= authsHashOwners[_owner][_hkey][_idx];
        auth_record storage ar= auths[_authIdx];
        return (ar.dataSource, ar.hash, ar.owner, ar.recipient, ar.comment, ar.time, ar.validity);
	}

    // This function checks if an authorization has already existed between two addresses and a given hash. It takes three parameters, the address of the owner, the address of the recipient, and a bytes data type for the hash. It returns a boolean value of true or false depending on whether or not an authorization has already existed. 
    /** 
    * @dev Checks if an authorization has already existed between two addresses and a given hash 
    * @param _owner The address of the owner 
    * @param _recipient The address of the recipient 
    * @param _hash A bytes data type for the hash 
    * @return A boolean value indicating whether or not an authorization has already existed 
    */
    function authorizationHasExisted(address _owner, address _recipient, bytes memory _hash) public view returns (bool) {
        bytes32 _ukey= getUniqueHashKey(_owner, _recipient, _hash);
        if(uniqueHashAuths[_ukey].length==0) return false;
        return true;
	}

    // This function is used to validate an authorization between two addresses. It takes in the address of the owner, address of the recipient, and a hash as parameters. It then creates a unique key based on these parameters and checks if there are any authorization records associated with this key. If there are, it takes the first one and checks if it is still valid (if its validity is greater than the current time). If so, it returns true, otherwise false.
    /**
    * @dev Validates an authorization between two addresses using a hash
    * @param _owner The address of the owner 
    * @param _recipient The address of the recipient 
    * @param _hash The hash associated with the authorization 
    * @return bool True if the authorization is valid, false otherwise 
    */
    function authorizationValidated(address _owner, address _recipient, bytes memory _hash) public view returns (bool) {
        bytes32 _ukey= getUniqueHashKey(_owner, _recipient, _hash);
        if(uniqueHashAuths[_ukey].length==0) return false;

        uint256 _authIdx= uniqueHashAuths[_ukey][0];
        auth_record storage ar= auths[_authIdx];
        return (ar.validity > now)?true:false;
	}

    function getHashKey(bytes memory _hash) public pure returns (bytes32) {
        return keccak256(_hash);
    }

    function getUniqueHashKey(address _owner, address _recipient, bytes memory _hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_owner, _recipient, _hash));
    }    

    function getAuthorizationMessageHashToSign(bytes memory _hash, address _recipient, uint256 _nonce) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), _hash, _recipient, _nonce));
    }

}
/**
 * Mailvelope - secure email with OpenPGP encryption for Webmail
 * Copyright (C) 2012  Thomas Oberndörfer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


define(function(require, exports, module) {

  var openpgp = require('openpgp');
  var mvelo = require('../lib-mvelo').mvelo;
  var goog = require('./closure-library/closure/goog/emailaddress').goog;
  var keyring = new openpgp.Keyring();
  

  openpgp.addSubpacketExtractor(1, function (contentBytes) {
    var result;

    result = {
      'dataUri': "data:image/jpg;charset=utf-8;base64,/9j/4QAyRXhpZgAASUkqAAgAAAABAJiCAgAOAAAAGgAAAAAAAABUT0REIENSQVdGT1JEAAAA/+wAEUR1Y2t5AAEABAAAAB4AAP/hA/hodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo1Q0VEOTY3QUIyMDIxMUUzQkM0Rjg4Mzc0QUNEMzFCMCIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo1Q0VEOTY3OUIyMDIxMUUzQkM0Rjg4Mzc0QUNEMzFCMCIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M1IE1hY2ludG9zaCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJFOTQ0QjBCOTBEMkJBOTU5NzU5MkQyMzRERDM0N0Y0MyIgc3RSZWY6ZG9jdW1lbnRJRD0iRTk0NEIwQjkwRDJCQTk1OTc1OTJEMjM0REQzNDdGNDMiLz4gPGRjOnJpZ2h0cz4gPHJkZjpBbHQ+IDxyZGY6bGkgeG1sOmxhbmc9IngtZGVmYXVs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"
    }
  
    return {'data': result};
  });

  openpgp.addSubpacketExtractor(100, function (contentBytes) {
    function stringToBytes ( str ) {
      //  code taken from http://stackoverflow.com/a/1242596
      var ch, st, re = [];
      for (var i = 0; i < str.length; i++ ) {
        ch = str.charCodeAt(i);  // get char 
        st = [];                 // set up "stack"
        do {
          st.push( ch & 0xFF );  // push byte to stack
          ch = ch >> 8;          // shift value down by 1 byte
        }  
        while ( ch );
        // add stack contents to result
        // done because chars have "wrong" endianness
        re = re.concat( st.reverse() );
      }
      // return an array of bytes
      return re;
    };

    function byteArrayToLong (byteArray) {
      //  code taken from http://stackoverflow.com/a/12965194
      var value = 0;
      for ( var i = byteArray.length - 1; i >= 0; i--) {
        value = (value * 256) + byteArray[i];
      }

      return value;
    };
  
    function bytesToHex (bytes) {
      //  code taken from https://code.google.com/p/crypto-js/source/browse/branches/2.0.x/src/Crypto.js?spec=svn301&r=301#61
      for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
      }
      return hex.join("");
    };

    var bytes = stringToBytes(contentBytes);
    var result;
  
    result = {
      'version': bytes[0],
      'priority': byteArrayToLong(bytes.slice(5, 9)),
      'coin': '79f58f10-e5b8-4807-94e5-472a2a623f30',
      'value': bytesToHex(bytes.slice(10))
    }

    return {'data':result};
  });

  function getKeys() {
    // map keys to UI format
    var keys = getPublicKeys().concat(getPrivateKeys());
    // sort by key type and name
    keys = keys.sort(function(a, b) {
      var compType = a.type.localeCompare(b.type);
      if (compType === 0) {
        return a.name.localeCompare(b.name);
      } else {
        return compType;
      }
    });
    return keys;
  }

  function setOpenPGPComment(text) {
    openpgp.config.commentstring = text;
  }

  function setOpenPGPVersion(text) {
    openpgp.config.versionstring = text;
  }

  function getPublicKeys() {
    return mapKeys(keyring.publicKeys.keys);
  }

  function getPrivateKeys() {
    return mapKeys(keyring.privateKeys.keys);
  }

  function mapKeys(keys) {
    var result = [];
    keys.forEach(function(key) {
      var uiKey = {};
      if (key.isPublic()) {
        uiKey.type = 'public';
      } else {
        uiKey.type = 'private';
      }
      try {
        uiKey.validity = key.verifyPrimaryKey() === openpgp.enums.keyStatus.valid;
      } catch (e) {
        uiKey.validity = false;
        console.log('Exception in verifyPrimaryKey', e);
      }
      // fingerprint used as UID
      uiKey.guid = key.primaryKey.getFingerprint();
      uiKey.id = key.primaryKey.getKeyId().toHex().toUpperCase();
      uiKey.fingerprint = uiKey.guid.toUpperCase();
      // primary user
      try {
        var address = goog.format.EmailAddress.parse(getUserId(key));
        uiKey.name = address.getName();
        uiKey.email = address.getAddress();
        uiKey.exDate = key.getExpirationTime();
        if (uiKey.exDate) {
          uiKey.exDate = uiKey.exDate.toISOString();
        } else {
          uiKey.exDate = 'The key does not expire';
        }
      } catch (e) {
        uiKey.name = uiKey.name || 'NO USERID FOUND';
        uiKey.email = uiKey.email || 'UNKNOWN';
        uiKey.exDate = uiKey.exDate || 'UNKNOWN';
        console.log('Exception map primary user', e);
      }
      uiKey.crDate = key.primaryKey.created.toISOString();
      uiKey.algorithm = getAlgorithmString(key.primaryKey.algorithm);
      uiKey.bitLength = key.primaryKey.getBitSize();
      result.push(uiKey);
    });
    return result;
  }

  function getKeyDetails(guid) {
    var details = {};
    var keys = keyring.getKeysForId(guid);
    if (keys) {
      var key = keys[0];
      // subkeys
      mapSubKeys(key.subKeys, details);
      // users
      mapUsers(key.users, details);
      // user attributes
      mapAttributes(key.users, details);
      return details;
    } else {
      throw new Error('Key with this fingerprint not found: ', guid);
    }
  }

  exports.setOpenPGPComment = setOpenPGPComment;
  exports.setOpenPGPVersion = setOpenPGPVersion;
  exports.getKeys = getKeys;
  exports.getPublicKeys = getPublicKeys;
  exports.getPrivateKeys = getPrivateKeys;
  exports.getKeyDetails = getKeyDetails;

  function mapSubKeys(subkeys, toKey) {
    toKey.subkeys = [];
    subkeys && subkeys.forEach(function(subkey) {
      try {
        var skey = {};
        skey.crDate = subkey.subKey.created.toISOString();
        skey.exDate = subkey.getExpirationTime();
        if (skey.exDate) {
          skey.exDate = skey.exDate.toISOString();
        } else {
          skey.exDate = 'The key does not expire';
        }
        skey.id = subkey.subKey.getKeyId().toHex().toUpperCase();
        skey.algorithm = getAlgorithmString(subkey.subKey.algorithm);
        skey.bitLength = subkey.subKey.getBitSize();
        skey.fingerprint = subkey.subKey.getFingerprint().toUpperCase();
        toKey.subkeys.push(skey);
      } catch (e) {
        console.log('Exception in mapSubKeys', e);
      }
    });
  }

  function mapUsers(users, toKey) {
    toKey.users = [];
    users && users.forEach(function(user) {
      try {
        var uiUser = {};
        uiUser.userID = user.userId.userid;
        uiUser.signatures = [];
        user.selfCertifications && user.selfCertifications.forEach(function(selfCert) {
          var sig = {};
          sig.signer = user.userId.userid;
          sig.id = selfCert.issuerKeyId.toHex().toUpperCase();
          sig.crDate = selfCert.created.toISOString();
          uiUser.signatures.push(sig);
        });
        user.otherCertifications && user.otherCertifications.forEach(function(otherCert) {
          var sig = {};
          var keyidHex = otherCert.issuerKeyId.toHex();
          var issuerKeys = keyring.getKeysForId(keyidHex);
          if (issuerKeys !== null) {
            sig.signer = getUserId(issuerKeys[0]);
          } else {
            sig.signer = 'Unknown Signer';
          }
          sig.id = otherCert.issuerKeyId.toHex().toUpperCase();
          sig.crDate = otherCert.created.toISOString();
          uiUser.signatures.push(sig);
        });
        toKey.users.push(uiUser);
      } catch (e) {
        console.log('Exception in mapUsers', e);
      }
    });
  }

  function mapAttributes(users, toKey) {
    toKey.attributes = [];
    users && users.filter(function(user) {return user.userAttribute != null;}).forEach(function(user) {
      try {
        user.userAttribute.attributes.forEach(function(attribute) {
          var uiAttribute = {};

          uiAttribute.tag = attribute.tag;
          if (attribute.tag == 1) {
            uiAttribute.tagName = "Image";
          } else if (attribute.tag == 100) {
            uiAttribute.tagName = "BTC";
          } else {
            uiAttribute.tagName = "Unknown";
          };
          
          uiAttribute.content = attribute.content;
          
          if (typeof(attribute.data) != 'undefined') {
            uiAttribute.data = JSON.parse(JSON.stringify(attribute.data));
          }
          toKey.attributes.push(uiAttribute);
          console.log("Added uiAttribute", uiAttribute);
        });
      } catch (e) {
        console.log('Exception in mapAttributes', e);
      }
    });
  }

  function getKeyUserIDs(proposal) {
    var result = [];
    keyring.getAllKeys().forEach(function(key) {
      if (key.verifyPrimaryKey() === openpgp.enums.keyStatus.valid) {
        var user = {};
        mapKeyUserIds(key, user, proposal)
        result.push(user);
      }
    });
    result = result.sort(function(a, b) {
      return a.userid.localeCompare(b.userid);
    });
    return result;
  }

  function mapKeyUserIds(key, user, proposal) {
    user.keyid = key.primaryKey.getKeyId().toHex();
    try {
      user.userid = getUserId(key);
      var email = goog.format.EmailAddress.parse(user.userid).getAddress();
      user.proposal = proposal.some(function(element) {
        return email === element;
      });
    } catch (e) {
      user.userid = user.userid || 'UNKNOWN';
      console.log('Exception in mapKeyUserIds', e);
    }
  }

  function importPublicKey(armored) {
    var result = [];
    var imported = openpgp.key.readArmored(armored);
    if (imported.err) {
      imported.err.forEach(function(error) {
        console.log('Error on key.readArmored', error);
        result.push({
          type: 'error',
          message: 'Unable to read one public key: ' + error.message
        });
      });
    }
    imported.keys.forEach(function(pubKey) {
      // check for existing keys
      var key = keyring.getKeysForId(pubKey.primaryKey.getFingerprint());
      var keyid = pubKey.primaryKey.getKeyId().toHex().toUpperCase();
      if (key) {
        key = key[0];
        key.update(pubKey);
        result.push({
          type: 'success',
          message: 'Public key ' + keyid + ' of user ' + getUserId(pubKey) + ' updated'
        });
      } else {
        keyring.publicKeys.push(pubKey);
        result.push({
          type: 'success',
          message: 'Public key ' + keyid + ' of user ' + getUserId(pubKey) + ' imported into key ring'
        });
      }
    });
    return result;
  }

  function importPrivateKey(armored) {
    var result = [];
    var imported = openpgp.key.readArmored(armored);
    if (imported.err) {
      imported.err.forEach(function(error) {
        console.log('Error on key.readArmored', error);
        result.push({
          type: 'error',
          message: 'Unable to read one private key: ' + error.message
        });
      });
    }
    imported.keys.forEach(function(privKey) {
      // check for existing keys
      var key = keyring.getKeysForId(privKey.primaryKey.getFingerprint());
      var keyid = privKey.primaryKey.getKeyId().toHex().toUpperCase();
      if (key) {
        key = key[0];
        if (key.isPublic()) {
          privKey.update(key);
          keyring.publicKeys.removeForId(privKey.primaryKey.getFingerprint());
          keyring.privateKeys.push(privKey);
          result.push({
            type: 'success',
            message: 'Private key of existing public key' + keyid + ' of user ' + getUserId(privKey) + ' imported into key ring'
          });
        } else {
          key.update(privKey);
          result.push({
            type: 'success',
            message: 'Private key ' + keyid + ' of user ' + getUserId(privKey) + ' updated'
          });
        }
      } else {
        keyring.privateKeys.push(privKey);
        result.push({
          type: 'success',
          message: 'Private key ' + keyid + ' of user ' + getUserId(privKey) + ' imported into key ring'
        });
      }

    });
    return result;
  }

  function importKeys(armoredKeys) {
    var result = [];
    // sort, public keys first
    armoredKeys = armoredKeys.sort(function(a, b) {
      return b.type.localeCompare(a.type);
    });
    // import
    armoredKeys.forEach(function(key) {
      if (key.type === 'public') {
        result = result.concat(importPublicKey(key.armored));
      } else if (key.type === 'private') {
        result = result.concat(importPrivateKey(key.armored));
      }
    });
    // store if import succeeded
    if (result.some(function(message) { return message.type === 'success'})) {
      keyring.store();
    }
    return result;
  }

  function getAlgorithmString(keyType) {
    var result = '';
    switch (keyType) {
    case 'rsa_encrypt_sign':
        result = "RSA (Encrypt or Sign)";
        break;
    case 'rsa_encrypt':
        result = "RSA Encrypt-Only";
        break;
    case 'rsa_sign':
        result = "RSA Sign-Only";
        break;
    case 'elgamal':
        result = "Elgamal (Encrypt-Only)";
        break;
    case 'dsa':
        result = "DSA (Digital Signature Algorithm)";
        break;
    default:
        result = "UNKNOWN";
    }
    return result;
  }

  function getKeyType(algorithm) {
    var result;
    switch (algorithm) {
    case "RSA/RSA":
        result = openpgp.enums.publicKey.rsa_encrypt_sign;
        break;
    case "DSA/ElGamal":
        result = openpgp.enums.publicKey.dsa;
        break;
    default:
        throw new Error('Key type not supported');
    }
    return result;
  }

  function decode_utf8(str) {
    // if str contains umlauts (öäü) this throws an exeception -> no decoding required
    try {
      return decodeURIComponent(escape(str));
    } catch (e) {
      return str;
    }
  }

  function removeKey(guid, type) {
    keyring.removeKeysForId(guid);
    keyring.store();
  }

  function validateEmail(email) {
    return goog.format.EmailAddress.isValidAddrSpec(email);
  }

  function generateKey(options) {
    var keyType = getKeyType(options.algorithm);
    var emailAdr = new goog.format.EmailAddress(options.email, options.user);
    var keyPair = openpgp.generateKeyPair(keyType, parseInt(options.numBits), emailAdr.toString(), options.passphrase);
    keyring.privateKeys.push(keyPair.key);
    keyring.store();
    return true;
  }

  function getUserId(key) {
    var primaryUser = key.getPrimaryUser();
    if (primaryUser) {
      return primaryUser.user.userId.userid;
    } else {
      return key.users[0].userId.userid;
    }
  }

  function readMessage(armoredText) {
    var result = {};
    try {
      result.message = openpgp.message.readArmored(armoredText);
    } catch (e) {
      console.log('openpgp.message.readArmored', e);
      throw {
        type: 'error',
        message: 'Could not read this encrypted message: ' + e
      }
    }

    result.key = null;
    result.userid = '';
    result.keyid = null;

    var encryptionKeyIds = result.message.getEncryptionKeyIds();
    for (var i = 0; i < encryptionKeyIds.length; i++) {
      result.keyid = encryptionKeyIds[i].toHex();
      result.key = keyring.privateKeys.getForId(result.keyid, true);
      if (result.key) {
        break;
      }
    }

    if (result.key) {
      result.userid = getUserId(result.key);
    } else {
      // unknown private key
      result.keyid = encryptionKeyIds[0].toHex();
      var message = 'No private key found for this message. Required private key IDs: ' + result.keyid.toUpperCase();
      for (var i = 1; i < encryptionKeyIds.length; i++) {
        message = message + ' or ' + encryptionKeyIds[i].toHex().toUpperCase();
      }
      throw {
        type: 'error',
        message: message,
      }
    }

    return result;
  }

  function unlockKey(privKey, keyid, passwd) {
    var keyIdObj = new openpgp.Keyid();
    // TODO OpenPGP.js helper method
    keyIdObj.read(openpgp.util.hex2bin(keyid));
    try {
      return privKey.decryptKeyPacket([keyIdObj], passwd);
    } catch (e) {
      throw {
        type: 'error',
        message: 'Could not unlock the private key'
      }
    }
  }

  function decryptMessage(message, callback) {
    try {
      var decryptedMsg = openpgp.decryptMessage(message.key, message.message);
      //decryptedMsg = decode_utf8(decryptedMsg);
      callback(null, decryptedMsg);
    } catch (e) {
      callback({
        type: 'error',
        message: 'Could not decrypt this message: ' + e
      });
    }
  }

  function encryptMessage(message, keyIdsHex, callback) {
    var keys = keyIdsHex.map(function(keyIdHex) {
      var keyArray = keyring.getKeysForId(keyIdHex);
      return keyArray ? keyArray[0] : null;
    }).filter(function(key) {
      return key !== null;
    });
    if (keys.length === 0) {
      callback({
        type: 'error',
        message: 'No valid key found for enryption'
      });
    }
    try {
      var encrypted = openpgp.encryptMessage(keys, message);
      callback(null, encrypted);
    } catch (e) {
      callback({
        type: 'error',
        message: 'Could not encrypt this message'
      });
    }
  }

  function getKeyForSigning(keyIdHex) {
    var key = keyring.privateKeys.getForId(keyIdHex);
    var userId = getUserId(key);
    return {
      signKey: key,
      userId : userId
    }
  }

  function signMessage(message, signKey, callback) {
    try {
      var signed = openpgp.signClearMessage([signKey], message);
      callback(null, signed);
    } catch (e) {
      callback({
        type: 'error',
        message: 'Could not sign this message'
      });
    }
  }

  function getWatchList() {
    return mvelo.storage.get('mailvelopeWatchList');
  }

  function setWatchList(watchList) {
    mvelo.storage.set('mailvelopeWatchList', watchList);
  }

  function getHostname(url) {
    var hostname = mvelo.util.getHostname(url);
    // limit to 3 labels per domain
    return hostname.split('.').slice(-3).join('.');
  }

  exports.getKeyUserIDs = getKeyUserIDs;
  exports.getKeyForSigning = getKeyForSigning;
  exports.importKeys = importKeys;
  exports.removeKey = removeKey;
  exports.validateEmail = validateEmail;
  exports.generateKey = generateKey;
  exports.readMessage = readMessage;
  exports.decryptMessage = decryptMessage;
  exports.unlockKey = unlockKey;
  exports.encryptMessage = encryptMessage;
  exports.signMessage = signMessage;
  exports.getWatchList = getWatchList;
  exports.setWatchList = setWatchList;
  exports.getHostname = getHostname;
  exports.getHost = mvelo.util.getHost;

  function getPreferences() {
    return mvelo.storage.get('mailvelopePreferences');
  }

  function setPreferences(preferences) {
    mvelo.storage.set('mailvelopePreferences', preferences);
  }

  exports.getPreferences = getPreferences;
  exports.setPreferences = setPreferences;

});

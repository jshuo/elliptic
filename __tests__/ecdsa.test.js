/* eslint-env node, mocha */
'use strict';

var assert = require('assert');
var elliptic = require('../');
var Signature = require('../lib/elliptic/ec/signature');
var BN = require('bn.js');
var hash = require('hash.js');

var entropy = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25,
];

var msg = 'deadbeef';

describe('ECDSA', function() {


  it('should recover the public key from a signature', function() {
    var ec = new elliptic.ec('p256');
   
    // var key = ec.genKeyPair();
    // const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
    // const publicKey_x = '14c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
    // const publicKey_y = 'ec41869995bd661849414c523c7dff9a96f1c8dbc2e5e78172118f91c7199869'

    const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8';
    const key = ec.keyFromPrivate(privateKey);
    const publicKey = key.getPublic();
    var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
    var signature = key.sign(msg);
    var recid = ec.getKeyRecoveryParam(msg, signature, key.getPublic());

    var r =  ec.recoverPubKey(msg, signature, recid);
    console.log('recid: ', recid, 'public key: ', key.getPublic().encode('hex'));
    console.log('Public key x:', key.getPublic().getX().toString('hex'));
   console.log('Public key y:', key.getPublic().getY().toString('hex'));
    assert(key.getPublic().eq(r), 'the keys should match');
  });

});

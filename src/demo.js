import * as jose from 'jose';
import crypto from 'crypto';

import CONFIG from './config.json' assert { type: "json" };
const DID = `did:web:${CONFIG.DOMAIN}:${CONFIG.REPOSITORY}`;

import JWK from '../keys/jwk.json' assert { type: "json" };
console.log(JWK);

import * as didJWT from 'did-jwt';
const signer = didJWT.ES256KSigner(didJWT.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

let jwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer },
  { alg: 'ES256K' }
)
console.log(jwt)

import * as Resolver from 'did-resolver';
import { getResolver } from 'web-did-resolver';



const main = async () => {
  console.log('=== Import JWK ===');
  const privateKey = await jose.importJWK(JWK, 'ES256K');

  console.log('=== Sign with JWK ===');
  const jwt = new jose.SignJWT({ 'claim': 'this is Example Claim' })
    .setProtectedHeader({ alg: 'ES256K' })
    .setIssuedAt()
    .setIssuer(DID)
    .setAudience('urn:example:audience')
  const signed = await jwt.sign(privateKey);
  console.log(`Signed JWT: ${signed}`);

  console.log('=== Verify JWK with did-jwt ===');
  const webResolver = getResolver();
  const didResolver = new Resolver.Resolver({
    ...webResolver
  });
  let verificationResponse = await didJWT.verifyJWT(signed, {
    resolver: didResolver,
    audience: 'urn:example:audience'
  }).catch((e) => {
    console.log("Error1");
    console.error(e);
    return undefined;
  });
  if (verificationResponse === undefined) {
    console.log('Verify JWK Failed')
    return;
  }
  console.log('Verify JWK Success')
  console.log(verificationResponse)
}

main();
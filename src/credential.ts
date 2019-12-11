import * as x509 from '@fidm/x509';
import * as cbor from 'cbor';
import jseu from 'js-encoding-utils';
import {getJscu} from './env';
import {coseToJwk} from "./util";

const checkCredentialId = (
  credential: PublicKeyCredential
): boolean => credential.id === jseu.encoder.encodeBase64Url(new Uint8Array(credential.rawId));

const checkResponse = async (
  clientData: Uint8Array,
  authData: Uint8Array,
  type: 'webauthn.create'|'webauthn.get',
  challenge: Uint8Array
): Promise<{valid: boolean, msg: string}> => {
  const jscu = getJscu();

  const clientDataJson = JSON.parse(jseu.encoder.arrayBufferToString(clientData));
  if(clientDataJson.type !== type) return {valid: false, msg: 'InvalidType'};
  if(jseu.encoder.encodeBase64Url(challenge) !== clientDataJson.challenge) return {valid: false, msg: 'InvalidChallenge'};

  // check and parse authData https://www.w3.org/TR/webauthn/#authenticator-data
  const rpId = (new URL(clientDataJson.origin)).hostname;
  const rpIdHash = await jscu.hash.compute(jseu.encoder.stringToArrayBuffer(rpId), 'SHA-256');
  // check rpIdHash
  if (jseu.encoder.encodeBase64(authData.slice(0, 32)) !== jseu.encoder.encodeBase64(rpIdHash)) return {valid: false, msg: 'InvalidRpIdHash'};

  // check flag: TODO: Adapted only to Security Key By Yubico
  const flag = new Uint8Array([authData[32]]);
  if ((flag[0] & 0x01) !== 0x01) return {valid: false, msg: 'InvalidFlag'}; // check user present flag
  if (type === 'webauthn.create' && (flag[0] & 0x40) !== 0x40) return {valid: false, msg: 'InvalidFlag'}; // attestedCredentialData flag
  // TODO check clientExtensionResults and others from step 12...

  return {valid: true, msg: 'ok'};
};

const parseAttestedCredentialData = async (
  authData: Uint8Array
): Promise<{aaguid: Uint8Array, credentialId: string, publicKeyPem: string}> => {
  const tailer = authData.slice(37, authData.length);
  const aaguid = tailer.slice(0, 16);
  const credentialIdLength = (<number>tailer[16] << 8) + <number>tailer[17];
  const credentialId = tailer.slice(18, 18+credentialIdLength);
  const attestedCredentialsBuf = tailer.slice(18+credentialIdLength, tailer.length);
  const jwk = coseToJwk(attestedCredentialsBuf);
  const pemKey = await (new (getJscu()).Key('jwk', jwk)).export('pem');

  return {aaguid, credentialId: jseu.encoder.encodeBase64Url(credentialId), publicKeyPem: pemKey};
};

export const extractPublicKeyFromPublicKeyCredential = async (
  credential: PublicKeyCredential,
  challenge: Uint8Array
): Promise<{valid: boolean, publicKey?: string}> => {
  const jscu = getJscu();
  // https://www.w3.org/TR/webauthn/#registering-a-new-credential
  //check Id
  if (!checkCredentialId(credential)) return {valid: false};

  // AuthenticatorAttestationResponse
  const response = (<AuthenticatorAttestationResponse>(credential).response);
  const attestationObjectDecoded = cbor.decodeAllSync(Buffer.from(response.attestationObject));
  const authData = attestationObjectDecoded[0].authData;

  // check clientDataJson and authData
  const r = await checkResponse(new Uint8Array(response.clientDataJSON), authData, 'webauthn.create', challenge);
  if(!r.valid) {console.log(r.msg); return {valid: false};}
  const clientDataHash = await jscu.hash.compute(new Uint8Array(response.clientDataJSON), 'SHA-256');

  // TODO: Adapted only to Security Key By Yubico
  const fmt = attestationObjectDecoded[0].fmt;
  const attStmt = attestationObjectDecoded[0].attStmt; // attestation statement
  if(fmt === 'packed') {
    // to be verified for 'packed'
    const verificationData = new Uint8Array(authData.length + clientDataHash.length);
    verificationData.set(authData, 0);
    verificationData.set(clientDataHash, authData.length);

    // extract public key cert generated at Security Key By Yubico
    const pemCert = jseu.formatter.binToPem(new Uint8Array(attStmt.x5c[0]), 'certificate');
    const crt = x509.Certificate.fromPEM(Buffer.from(jseu.encoder.stringToArrayBuffer(pemCert)));
    const jscuKeyObj = new jscu.Key('der', new Uint8Array(crt.publicKey.toDER()));

    // signature to be verified
    const signature = new Uint8Array(attStmt.sig);

    // @ts-ignore
    const validateSig = await jscu.pkc.verify(new Uint8Array(verificationData), signature, jscuKeyObj, 'SHA-256', {format: 'der'});
    if(!validateSig) return {valid: false};

    // Get Public Key From AuthData
    const parsed = await parseAttestedCredentialData(new Uint8Array(authData));
    return {valid:true, publicKey: parsed.publicKeyPem};
  }
  else return {valid: false};
};

export const getPublicKeyIdFromAssertion = (assertion: PublicKeyCredential): Uint8Array => new Uint8Array(assertion.rawId);


export const verifyAssertion = async (
  assertion: PublicKeyCredential,
  challenge: Uint8Array,
  publicKeyPem: string
): Promise<{valid: boolean, msg: string}> => {
  const jscu = getJscu();

  // Verifying the assertion for user authentication
  // https://www.w3.org/TR/webauthn/#verifying-assertion
  if (!checkCredentialId(assertion)) return {valid: false, msg: 'InvalidId'};

  // AuthenticatorAssertionResponse
  const response = (<AuthenticatorAssertionResponse>(assertion).response);
  const authData = new Uint8Array(response.authenticatorData);
  const signature = new Uint8Array(response.signature);
  const clientDataHash = await jscu.hash.compute(new Uint8Array(response.clientDataJSON), 'SHA-256');

  // check clientDataJson and authData
  const r = await checkResponse(new Uint8Array(response.clientDataJSON), authData, 'webauthn.get', challenge);
  if(!r.valid) {console.log(r.msg); return {valid: false, msg: r.msg};}

  const verificationData = new Uint8Array(authData.length + clientDataHash.length);
  verificationData.set(authData, 0);
  verificationData.set(clientDataHash, authData.length);
  console.log(authData.toString());
  console.log(clientDataHash.toString());
  console.log(verificationData.toString());

  const jscuKeyObj = new jscu.Key('pem', publicKeyPem);
  const x = await jscu.pkc.verify(verificationData, signature, jscuKeyObj, 'SHA-256', {format: 'der'});
  console.log(x);
  return {valid: true, msg: 'ok'};
};

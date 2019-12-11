import * as x509 from '@fidm/x509';
import * as cbor from 'cbor';
import jseu from 'js-encoding-utils';
import {getJscu} from './env';


export const extractPublicKeyFromPublicKeyCredential = async (credential: PublicKeyCredential): Promise<{valid: boolean, publicKey?: any}> => {
  const jscu = getJscu();
  // https://www.w3.org/TR/webauthn/#registering-a-new-credential

  //check Id
  if (credential.id !== jseu.encoder.encodeBase64Url(new Uint8Array(credential.rawId))) return {valid: false};

  // AuthenticatorAttestationResponse
  const response = (<AuthenticatorAttestationResponse>(credential).response);

  // check clientDataJson: verify https://www.w3.org/TR/webauthn/#registering-a-new-credential
  const clientDataJson = JSON.parse(jseu.encoder.arrayBufferToString(response.clientDataJSON));
  if(clientDataJson.type !== 'webauthn.create') return {valid: false};
  const clientDataHash = await jscu.hash.compute(new Uint8Array(response.clientDataJSON), 'SHA-256');

  // check authData
  const attestationObjectDecoded = cbor.decodeAllSync(Buffer.from(response.attestationObject));
  const authData = attestationObjectDecoded[0].authData;
  // parse authData: https://www.w3.org/TR/webauthn/#authenticator-data
  const rpId = (new URL(clientDataJson.origin)).hostname;
  const rpIdHash = await jscu.hash.compute(jseu.encoder.stringToArrayBuffer(rpId), 'SHA-256');

  // check rpIdHash
  if (jseu.encoder.encodeBase64(authData.slice(0, 32)) !== jseu.encoder.encodeBase64(rpIdHash)) return {valid: false};

  // check flag: TODO: Adapted only to Security Key By Yubico
  const flag = new Uint8Array([authData[32]]);
  if ((flag[0] & 0x01) !== 0x01) return {valid: false}; // check user present flag
  if ((flag[0] & 0x40) !== 0x40) return {valid: false}; // attestedCredentialData flag
  // TODO check clientExtensionResults and others from step 12...

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
    return {valid: await jscu.pkc.verify(new Uint8Array(verificationData), signature, jscuKeyObj, 'SHA-256', {format: 'der'}), publicKey: jscuKeyObj};
  }
  else return {valid: false};
};

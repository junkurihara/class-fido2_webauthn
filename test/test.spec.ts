import jscu from 'js-crypto-utils';
import * as chai from 'chai';
import {getTestEnv} from './prepare';

const expect = chai.expect;
const env = getTestEnv();
const library = env.library;
const message = env.message;
const envName = env.envName;

// Import default credential parameters defined in credential-params.ts
import {createCredentialDefaultArgs, getCredentialDefaultArgs} from './credential-params';

describe(`${envName}: Demo for User Registration`, () => {
  before( () => {
    console.log(message);
  });

  it('Validation and Key Extraction from AebAuthn Create Credential Procedure', async function () {
    this.timeout(200000);

    // Receive a random challenge from Relaying Party (here we use a mock...)
    // 本当はここはRPからもらった乱数を利用することに注意する。
    const randomChallenge: ArrayBuffer = (jscu.random.getRandomBytes(32)).buffer;
    const createCredential: CredentialCreationOptions = createCredentialDefaultArgs;
    (<any>createCredential.publicKey).challenge = randomChallenge;

    // Create Public Key Credential and get Credential Certificate and Attestation Certificate
    const cred: Credential|null = await window.navigator.credentials.create(createCredential);

    // Check and output PublicKeyCredential
    expect(cred !== null).to.equal(true);
    expect((<PublicKeyCredential>cred).type).to.equal('public-key');
    const credential = <PublicKeyCredential>cred;
    console.log('------ [Response from Authenticator: PublicKeyCredential] ------');
    console.log(`> Credential ID: ${credential.id}`);
    console.log(`> Credential Raw ID: ${credential.rawId}`);
    console.log(`> Credential Type: ${credential.type}`);
    const attRes = <AuthenticatorAttestationResponse>(credential.response);
    console.log(`> AuthenticatorAttestationResponse.clientDataJSON: ${attRes.clientDataJSON}`);
    console.log(`> AuthenticatorAttestationResponse.attestationObject: ${attRes.attestationObject}`);

    /////////////////////////////
    // Check the validity of PublicKeyCredential (attestation
    const createChallenge = (<any>createCredential.publicKey).challenge;
    const verifyAttestationResult = await library.verifyAttestation(credential, createChallenge);
    expect(verifyAttestationResult.valid).to.equal(true);

    expect(typeof verifyAttestationResult.credentialPublicKey === 'string').to.equal(true);
    expect(typeof verifyAttestationResult.attestationCertificate === 'string').to.equal(true);
    console.log('');
    console.log('------ [Verification result on PublicKeyCredential.AuthenticatorAttestationResponse] ------');
    console.log(`> Verification result: ${verifyAttestationResult.valid}`);
    console.log(`> Credential Public Key:\n${verifyAttestationResult.credentialPublicKey}`);
    console.log(`> Attestation Certificate:\n${verifyAttestationResult.attestationCertificate}`);


    ///////////////////////////////////////////////////////////////////
    getCredentialDefaultArgs.publicKey.allowCredentials = [{
      id: credential.rawId,
      transports: ['usb', 'nfc', 'ble'],
      type: 'public-key'
    }];

    // ASSERTION
    const assr: Credential|null = await window.navigator.credentials.get(getCredentialDefaultArgs);
    expect(assr !== null).to.equal(true);
    // PublicKeyCredential
    expect((<PublicKeyCredential>assr).type).to.equal('public-key');
    const assertion = <PublicKeyCredential>assr;
    console.log(`credential id for assertion: ${assertion.id}`);

    const getChallenge = getCredentialDefaultArgs.publicKey.challenge;
    const ver = await library.verifyAssertion(assertion, getChallenge, verifyAttestationResult.credentialPublicKey);
    console.log(ver);
  });
});

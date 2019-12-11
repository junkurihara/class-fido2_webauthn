import * as chai from 'chai';
const expect = chai.expect;
import {getTestEnv} from './prepare';
const env = getTestEnv();
const library = env.library;
const message = env.message;
const envName = env.envName;

describe(`${envName}: Create Credential for User Registration`, () => {
  before( () => {
    console.log(message);
  });

  it('Validation and Key Extraction from webauthn Create Credential Procedure', async function () {
    this.timeout(200000);
    const createCredentialDefaultArgs: CredentialCreationOptions = {
      publicKey: {
        // Relying Party (a.k.a. - Service):
        rp: {
          name: 'Acme'
        },

        // User:
        user: {
          id: new Uint8Array(16),
          name: 'john.p.smith@example.com',
          displayName: 'John P. Smith'
        },

        pubKeyCredParams: [{
          type: 'public-key',
          alg: -7
        }],

        attestation: 'direct',

        timeout: 60000,

        challenge: new Uint8Array([ // サーバーから暗号学的にランダムな値が送られていなければならない
          0x8C, 0x0A, 0x26, 0xFF, 0x22, 0x91, 0xC1, 0xE9, 0xB9, 0x4E, 0x2E, 0x17, 0x1A, 0x98, 0x6A, 0x73,
          0x71, 0x9D, 0x43, 0x48, 0xD5, 0xA7, 0x6A, 0x15, 0x7E, 0x38, 0x94, 0x52, 0x77, 0x97, 0x0F, 0xEF
        ]).buffer
      }
    };
    const cred: Credential|null = await window.navigator.credentials.create(createCredentialDefaultArgs);

    expect(cred !== null).to.equal(true);
    // PublicKeyCredential
    expect((<PublicKeyCredential>cred).type).to.equal('public-key');
    const credential = <PublicKeyCredential>cred;
    console.log(`credential id: ${credential.id}`);

    const res = await library.extractPublicKeyFromPublicKeyCredential(credential);
    expect(res.valid).to.equal(true);

    const pem = await res.publicKey.export('pem');
    expect(typeof pem === 'string').to.equal(true);
    console.log(`extracted public key in pem:\n ${pem}`);
  });
});

/**
 * index.ts
 */

import * as x5c from './credential';

export const verifyAttestation = x5c.verifyAttestation;
export const verifyAssertion = x5c.verifyAssertion;
export const getPublicKeyIdFromAssertion = x5c.getPublicKeyIdFromAssertion;
export default {verifyAttestation, verifyAssertion, getPublicKeyIdFromAssertion};

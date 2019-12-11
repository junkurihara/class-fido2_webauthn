/**
 * index.ts
 */

import * as x5c from './credential';

export const extractPublicKeyFromPublicKeyCredential = x5c.extractPublicKeyFromPublicKeyCredential;
export const verifyAssertion = x5c.verifyAssertion;
export const getPublicKeyIdFromAssertion = x5c.getPublicKeyIdFromAssertion;
export default {extractPublicKeyFromPublicKeyCredential, verifyAssertion, getPublicKeyIdFromAssertion};

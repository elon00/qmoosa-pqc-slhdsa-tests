import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SLH_DSA_SHA2_128S,
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHAKE_128S,
  constantTimeEqual
} from '@qmoosa/pqc-slhdsa-protocol';
import { SlhDsaEngine } from '@qmoosa/pqc-slhdsa-engine';
import {
  SlhDsaClient,
  canonicalTransactionHash
} from '@qmoosa/pqc-slhdsa-sdk';

test('Integration Reality: Cross-Subsystem End-to-End Web4 Transaction Lifecycle', () => {
  const client = new SlhDsaClient();

  // 1. Participant generates post-quantum signature keypair
  const alice = client.createKeyPair('SLH-DSA-SHA2-128f');
  assert.equal(alice.parameterSet, 'SLH-DSA-SHA2-128f');
  assert.equal(alice.publicKeyHex.length, SLH_DSA_SHA2_128F.publicKeyBytes * 2);
  assert.equal(alice.secretKeyHex.length, SLH_DSA_SHA2_128F.secretKeyBytes * 2);

  // 2. Construct Web4 transaction
  const tx = {
    chainId: '42161',
    nonce: 1042,
    fromAddress: '0xAlicePqcAccount',
    toAddress: '0xSovereignVault',
    value: '25000000000000000000',
    payloadHex: '0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111',
    contextString: 'QMOOSA-ARBITRUM-ONE-FIPS205-TX:42161'
  };

  // 3. Client signs transaction envelope
  const signedEnvelope = client.signTransaction(
    tx,
    alice.secretKeyHex,
    alice.publicKeyHex,
    'SLH-DSA-SHA2-128f'
  );

  assert.equal(signedEnvelope.chainId, '42161');
  assert.equal(signedEnvelope.signatureHex.length, SLH_DSA_SHA2_128F.signatureBytes * 2);

  // 4. Verifier validates envelope
  const isAuthentic = client.verifyTransaction(signedEnvelope);
  assert.equal(isAuthentic, true, 'Genuine transaction envelope must verify successfully in integration');
});

test('Integration Reality: Multi-Tier Parameter Set Signature Pipeline (128s, 128f, SHAKE-128s)', () => {
  const engine = new SlhDsaEngine();
  const client = new SlhDsaClient(engine);

  // Tier 1: SLH-DSA-SHA2-128f (Fast Signing)
  const fastSigner = client.createKeyPair('SLH-DSA-SHA2-128f');
  const fastPayload = new TextEncoder().encode('Fast Micro-Payment Transaction');
  const fastSig = client.signMessage(fastPayload, fastSigner.secretKeyHex, 'SLH-DSA-SHA2-128f', {
    context: 'MICRO-PAYMENT-CHANNEL'
  });
  assert.equal(
    client.verifySignature(fastSig.signatureHex, fastPayload, fastSigner.publicKeyHex, 'SLH-DSA-SHA2-128f', {
      context: 'MICRO-PAYMENT-CHANNEL'
    }),
    true
  );

  // Tier 2: SLH-DSA-SHA2-128s (Small Signature Optimization)
  const smallSigner = client.createKeyPair('SLH-DSA-SHA2-128s');
  const smallPayload = new TextEncoder().encode('Storage-Constrained Settlement Anchor');
  const smallSig = client.signMessage(smallPayload, smallSigner.secretKeyHex, 'SLH-DSA-SHA2-128s', {
    context: 'STORAGE-CONSTRAINED-ANCHOR'
  });
  assert.equal(
    client.verifySignature(smallSig.signatureHex, smallPayload, smallSigner.publicKeyHex, 'SLH-DSA-SHA2-128s', {
      context: 'STORAGE-CONSTRAINED-ANCHOR'
    }),
    true
  );

  // Tier 3: SLH-DSA-SHAKE-128s (Keccak Sponge Permutation)
  const shakeSigner = client.createKeyPair('SLH-DSA-SHAKE-128s');
  const shakePayload = new TextEncoder().encode('Keccak-Based Identity Commitment');
  const shakeSig = client.signMessage(shakePayload, shakeSigner.secretKeyHex, 'SLH-DSA-SHAKE-128s', {
    context: 'KECCAK-SPONGE-COMMITMENT'
  });
  assert.equal(
    client.verifySignature(shakeSig.signatureHex, shakePayload, shakeSigner.publicKeyHex, 'SLH-DSA-SHAKE-128s', {
      context: 'KECCAK-SPONGE-COMMITMENT'
    }),
    true
  );
});

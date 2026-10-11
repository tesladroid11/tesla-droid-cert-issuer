import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as asn1js from "asn1js";
import { createIssuerServer, loadOrCreateAccountKey, retryOrderNotReady, validateCsr } from "../src/server.js";

const require = createRequire(import.meta.url);
const acme = require("@root/acme");
const acmeCsr = require("@root/csr");

function makeCsrPem(nameOverride, keyPair) {
  const { privateKey, publicKey } = keyPair || generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiBytes = publicKey.export({ format: "der", type: "spki" });
  const hostname = nameOverride || `${createHash("sha256").update(spkiBytes).digest("hex").slice(0, 32)}.car.tesla-droid.app`;
  const spki = asn1js.fromBER(toArrayBuffer(spkiBytes)).result;
  const extension = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: "2.5.29.17" }),
      new asn1js.OctetString({
        valueHex: toArrayBuffer(new asn1js.Sequence({
          value: [
            new asn1js.Primitive({
              idBlock: { tagClass: 3, tagNumber: 2 },
              valueHex: toArrayBuffer(Buffer.from(hostname, "ascii")),
            }),
          ],
        }).toBER(false)),
      }),
    ],
  });
  const extensionRequest = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.9.14" }),
      new asn1js.Set({
        value: [new asn1js.Sequence({ value: [extension] })],
      }),
    ],
  });
  const requestInfo = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      new asn1js.Sequence({
        value: [
          new asn1js.Set({
            value: [new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                new asn1js.Utf8String({ value: hostname }),
              ],
            })],
          }),
        ],
      }),
      spki,
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [extensionRequest],
      }),
    ],
  });
  const requestInfoDer = Buffer.from(requestInfo.toBER(false));
  const signature = sign("sha256", requestInfoDer, privateKey);
  const csrDer = Buffer.from(new asn1js.Sequence({
    value: [
      requestInfo,
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: "1.2.840.10045.4.3.2" })],
      }),
      new asn1js.BitString({ valueHex: toArrayBuffer(signature) }),
    ],
  }).toBER(false));
  const base64 = csrDer.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE REQUEST-----\n${base64}\n-----END CERTIFICATE REQUEST-----`;
}

function toArrayBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${server.address().port}`;
}

test("accepts a signed P-256 CSR bound to its fingerprint-derived DNS name", () => {
  const csr = makeCsrPem();
  const result = validateCsr(csr, "car.tesla-droid.app");
  const acmeParsed = acmeCsr._info(result.csrDer);

  assert.match(result.fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(result.hostname, `${result.fingerprint.slice(0, 32)}.car.tesla-droid.app`);
  assert.ok(Buffer.isBuffer(result.csrDer));
  assert.equal(acmeParsed.subject, result.hostname);
  assert.deepEqual(acmeParsed.altnames, [result.hostname]);
  assert.equal(
    acme._csrToUrlBase64(result.csrDer),
    result.csrDer.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"),
  );
});

test("rejects a signed CSR whose name does not match its public key", () => {
  const csr = makeCsrPem("not-the-key-fingerprint.car.tesla-droid.app");

  assert.throws(
    () => validateCsr(csr, "car.tesla-droid.app"),
    /CSR name must match/,
  );
});

test("loads a persisted ACME account key from JSON", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "issuer-account-key-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));

  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const accountKey = privateKey.export({ format: "jwk" });
  await writeFile(join(stateDirectory, "acme-account-key.json"), JSON.stringify(accountKey));

  assert.deepEqual(await loadOrCreateAccountKey(stateDirectory), accountKey);
});

test("retries ACME orderNotReady responses with bounded backoff", async () => {
  let attempts = 0;
  const waits = [];
  const result = await retryOrderNotReady(async () => {
    attempts += 1;
    if (attempts < 3) {
      throw new Error(
        "Didn't finalize order: Unhandled status '403'. " +
        '{"type":"urn:ietf:params:acme:error:orderNotReady",' +
        '"detail":"Order status is processing"}',
      );
    }
    return "issued";
  }, async (duration) => waits.push(duration));

  assert.equal(result, "issued");
  assert.equal(attempts, 3);
  assert.deepEqual(waits, [3000, 7000]);
});

test("serves health and rejects malformed requests without issuing certificates", async (t) => {
  let issueCalls = 0;
  const server = createIssuerServer({
    config: { maxRequestsPerWindow: 5, domainSuffix: "car.tesla-droid.app" },
    issueCertificate: async () => {
      issueCalls += 1;
      return { cert: "pem", name: "device.car.tesla-droid.app", expires_at: 1 };
    },
  });
  const baseUrl = await listen(server);
  t.after(() => server.close());

  const health = await fetch(`${baseUrl}/healthz`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });

  const malformed = await fetch(`${baseUrl}/v1/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ csr: "not-a-csr" }),
  });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: "invalid_csr" });
  assert.equal(issueCalls, 0);
});

test("limits issuance requests from a single remote address", async (t) => {
  const server = createIssuerServer({
    config: { maxRequestsPerWindow: 1, domainSuffix: "car.tesla-droid.app" },
    issueCertificate: async () => ({ cert: "pem", name: "device", expires_at: 1 }),
  });
  const baseUrl = await listen(server);
  t.after(() => server.close());

  const send = () => fetch(`${baseUrl}/v1/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ csr: makeCsrPem() }),
  });
  assert.equal((await send()).status, 200);
  const limited = await send();
  assert.equal(limited.status, 429);
  assert.deepEqual(await limited.json(), { error: "rate_limit_exceeded" });
});

test("uses the trusted proxy client IP for rate limiting when enabled", async (t) => {
  const server = createIssuerServer({
    config: { maxRequestsPerWindow: 1, domainSuffix: "car.tesla-droid.app", trustProxy: true },
    issueCertificate: async () => ({ cert: "pem", name: "device", expires_at: 1 }),
  });
  const baseUrl = await listen(server);
  t.after(() => server.close());

  const send = (clientIp) => fetch(`${baseUrl}/v1/issue`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": clientIp,
    },
    body: JSON.stringify({ csr: makeCsrPem() }),
  });
  assert.equal((await send("192.0.2.1")).status, 200);
  assert.equal((await send("192.0.2.2")).status, 200);
  const limited = await send("192.0.2.1");
  assert.equal(limited.status, 429);
  assert.deepEqual(await limited.json(), { error: "rate_limit_exceeded" });
});

test("supports 6.0 ATTD challenge, enroll and status protocol with 16-hex name", async (t) => {
  let enrollCalledWith = null;
  const server = createIssuerServer({
    config: { maxRequestsPerWindow: 10, domainSuffix: "car.tesla-droid.app" },
    issueCertificate: async (csr) => {
      enrollCalledWith = csr;
      return { cert: "cert_pem_data", name: "16hexdevice.car.tesla-droid.app", expires_at: 1793456000 };
    },
  });
  const baseUrl = await listen(server);
  t.after(() => server.close());

  // 1. challenge
  const challengeRes = await fetch(`${baseUrl}/v1/challenge`);
  assert.equal(challengeRes.status, 200);
  const challengeBody = await challengeRes.json();
  assert.match(challengeBody.nonce, /^[0-9a-f]{32}$/);

  // 2. enroll with 16-hex name and 6.0 extra fields
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiBytes = publicKey.export({ format: "der", type: "spki" });
  const hostname16 = `${createHash("sha256").update(spkiBytes).digest("hex").slice(0, 16)}.car.tesla-droid.app`;
  const csr16 = makeCsrPem(hostname16, { privateKey, publicKey });

  const enrollRes = await fetch(`${baseUrl}/v1/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      csr: csr16,
      nonce: challengeBody.nonce,
      version_code: 263,
      drm_id: "test_drm",
      model: "Mi 10",
      android_id: "test_android",
    }),
  });
  assert.equal(enrollRes.status, 200);
  const enrollBody = await enrollRes.json();
  assert.equal(enrollBody.cert, "cert_pem_data");
  assert.equal(enrollBody.name, "16hexdevice.car.tesla-droid.app");
  assert.equal(enrollBody.expires_at, 1793456000);
  assert.equal(enrollCalledWith, csr16);

  // 3. status
  const statusRes = await fetch(`${baseUrl}/v1/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "streaming" }),
  });
  assert.equal(statusRes.status, 200);
  assert.deepEqual(await statusRes.json(), { status: "ok" });
});


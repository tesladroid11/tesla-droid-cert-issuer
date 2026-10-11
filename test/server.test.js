import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { once } from "node:events";
import test from "node:test";
import * as asn1js from "asn1js";
import { createIssuerServer, validateCsr } from "../src/server.js";

function makeCsrPem(nameOverride) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
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

  assert.match(result.fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(result.hostname, `${result.fingerprint.slice(0, 32)}.car.tesla-droid.app`);
});

test("rejects a signed CSR whose name does not match its public key", () => {
  const csr = makeCsrPem("not-the-key-fingerprint.car.tesla-droid.app");

  assert.throws(
    () => validateCsr(csr, "car.tesla-droid.app"),
    /CSR name must match/,
  );
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

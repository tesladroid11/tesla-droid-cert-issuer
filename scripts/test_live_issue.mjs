import { generateKeyPairSync, createHash, sign } from "node:crypto";
import * as asn1js from "asn1js";

function toArrayBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function makeCsrPem() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiBytes = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  const hostname = `${createHash("sha256").update(spkiBytes).digest("hex").slice(0, 32)}.car.tesla-droid.app`;
  console.log("Testing hostname:", hostname);
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

const csr = makeCsrPem();
console.log("Sending request to live server https://issuer.tesla-droid.app/v1/issue ...");
const startTime = Date.now();
try {
  const res = await fetch("https://issuer.tesla-droid.app/v1/issue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ csr }),
  });
  console.log(`HTTP Status: ${res.status} (took ${Date.now() - startTime}ms)`);
  const text = await res.text();
  console.log("Response:", text);
} catch (err) {
  console.error("Fetch failed:", err);
}

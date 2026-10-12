import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as asn1js from "asn1js";

function toArrayBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function makeCsrBase64(hostname, keyPair) {
  const { privateKey, publicKey } = keyPair;
  const spkiBytes = publicKey.export({ format: "der", type: "spki" });
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
  const csr = new asn1js.Sequence({
    value: [
      requestInfo,
      new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: "1.2.840.10045.4.3.2" })],
      }),
      new asn1js.BitString({ valueHex: toArrayBuffer(signature) }),
    ],
  });
  const der = Buffer.from(csr.toBER(false));
  return der.toString("base64");
}

async function main() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiBytes = publicKey.export({ format: "der", type: "spki" });
  const hostname16 = `${createHash("sha256").update(spkiBytes).digest("hex").slice(0, 16)}.car.tesla-droid.app`;
  const rawBase64Csr = makeCsrBase64(hostname16, { privateKey, publicKey });

  console.log(`Testing raw base64 CSR for ${hostname16} against https://issuer.tesla-droid.app...`);
  for (let attempt = 1; attempt <= 20; attempt++) {
    try {
      const res = await fetch("https://issuer.tesla-droid.app/v1/enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csr: rawBase64Csr }),
      });
      const data = await res.json();
      console.log(`[Attempt ${attempt}] HTTP ${res.status}:`, data);
      if (res.status === 200 && data.cert && data.name) {
        console.log("===> SUCCESS! Railway has deployed and verified raw base64 CSR!");
        return;
      }
    } catch (e) {
      console.log(`[Attempt ${attempt}] error:`, e.message);
    }
    await new Promise((r) => setTimeout(r, 4000));
  }
}

main();

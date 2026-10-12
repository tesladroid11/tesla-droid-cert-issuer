import { createServer } from "node:http";
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify, X509Certificate } from "node:crypto";
import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { Resolver, resolveTxt } from "node:dns/promises";
import { createRequire } from "node:module";
import * as asn1js from "asn1js";
import ACME from "@root/acme";

const require = createRequire(import.meta.url);
const Enc = require("@root/encoding/base64");
const U = require("@root/acme/utils.js");

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const defaultStateDirectory = resolve(moduleDirectory, "../data");
const defaultDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";
const maxBodyBytes = 16 * 1024;
const rateLimitWindowMs = 60 * 60 * 1000;
const certificateLimitWindowMs = 7 * 24 * 60 * 60 * 1000;
const maxRequestsPerWindow = 60;
const maxCertificatesPerWeek = 40;
const orderNotReadyRetryDelaysMs = [3000, 7000];
const issuerVersion = "0.1.0";

const memoryLogs = [];
function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ")}`;
  console.log(line);
  memoryLogs.push(line);
  if (memoryLogs.length > 200) memoryLogs.shift();
}

ACME._pollOrderStatus = async function (me, options, kid, order, verifieds) {
  const csr64 = ACME._csrToUrlBase64(options.csr);
  const payload = JSON.stringify({ csr: csr64 });
  const orderUrl = order._orderUrl;
  const finalizeUrl = order._finalizeUrl;

  const maxAttempts = 30;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) {
      await ACME._wait(me.retryInterval || 1500);
    }

    // RFC 8555 Section 7.4: poll the order resource via POST-as-GET
    let orderBody;
    try {
      const resp = await U._jwsRequest(me, {
        accountKey: options.accountKey,
        url: orderUrl,
        protected: { kid },
        payload: Enc.binToBuf(""),
      });
      orderBody = resp.body;
      ACME._notify(me, options, "certificate_status", {
        subject: options.domains[0],
        status: orderBody?.status,
      });
    } catch (err) {
      log(`Failed to fetch order status (attempt ${attempt}): ${err.message}`);
      continue;
    }

    if (orderBody?.status === "valid" && orderBody.certificate) {
      const voucher = orderBody;
      voucher._certificateUrl = orderBody.certificate;
      return voucher;
    }

    if (orderBody?.status === "invalid") {
      throw new Error(`[ACME.js] Order became invalid: ${JSON.stringify(orderBody)}`);
    }

    if (orderBody?.status === "processing") {
      continue;
    }

    if (orderBody?.status === "ready") {
      try {
        const finalizeResp = await U._jwsRequest(me, {
          accountKey: options.accountKey,
          url: finalizeUrl,
          protected: { kid },
          payload: Enc.strToBuf(payload),
        });
        const finBody = finalizeResp.body;
        ACME._notify(me, options, "certificate_status", {
          subject: options.domains[0],
          status: finBody?.status,
        });
        if (finBody?.status === "valid" && finBody.certificate) {
          const voucher = finBody;
          voucher._certificateUrl = finBody.certificate;
          return voucher;
        }
      } catch (err) {
        log(`Finalize request error (attempt ${attempt}): ${err.message || err.detail}`);
      }
      continue;
    }

    if (orderBody?.status === "pending") {
      continue;
    }
  }

  throw new Error(`[ACME.js] Timed out waiting for order finalization at ${orderUrl}`);
};

ACME._postChallenge = function (me, options, kid, auth) {
  const RETRY_INTERVAL = me.retryInterval || 1000;
  const DEAUTH_INTERVAL = me.deauthWait || 10 * 1000;
  const MAX_POLL = me.retryPoll || 8;
  const MAX_PEND = me.retryPending || 4;
  let count = 0;
  const altname = ACME._untame(auth.identifier.value, auth.wildcard);

  function deactivate() {
    return U._jwsRequest(me, {
      accountKey: options.accountKey,
      url: auth.url,
      protected: { kid },
      payload: Enc.strToBuf(JSON.stringify({ status: "deactivated" })),
    }).then(() => ACME._wait(DEAUTH_INTERVAL));
  }

  function pollStatus() {
    if (count >= MAX_POLL) {
      const err = new Error(`[ACME.js] stuck in bad pending/processing state for '${altname}'`);
      err.context = "present_challenge";
      return Promise.reject(err);
    }
    count += 1;
    return U._jwsRequest(me, {
      accountKey: options.accountKey,
      url: auth.url,
      protected: { kid },
      payload: Enc.binToBuf(""),
    })
      .then(checkResult)
      .catch(transformError);
  }

  function checkResult(resp) {
    ACME._notify(me, options, "challenge_status", {
      status: resp.body.status,
      type: auth.type,
      altname,
    });

    if (resp.body.status === "processing") {
      return ACME._wait(RETRY_INTERVAL).then(pollStatus);
    }

    if (resp.body.status === "pending") {
      if (count >= MAX_PEND) {
        return ACME._wait(RETRY_INTERVAL)
          .then(deactivate)
          .then(respondToChallenge);
      }
      // Poll with POST-as-GET instead of resending POST {}
      return ACME._wait(RETRY_INTERVAL).then(pollStatus);
    }

    try {
      options.challenges[auth.type]
        .remove({ challenge: auth })
        .catch((err) => {
          err.action = "challenge_remove";
          err.altname = auth.altname;
          err.type = auth.type;
          ACME._notify(me, options, "error", err);
        });
    } catch {}

    if (resp.body.status === "valid") {
      return resp.body;
    }

    let errmsg;
    if (!resp.body.status) {
      errmsg = `[ACME.js] (E_STATE_EMPTY) empty challenge state for '${altname}':${JSON.stringify(resp.body)}`;
    } else if (resp.body.status === "invalid") {
      errmsg = `[ACME.js] (E_STATE_INVALID) challenge state for '${altname}': '${JSON.stringify(resp.body)}'`;
    } else {
      errmsg = `[ACME.js] (E_STATE_UKN) challenge state for '${altname}': '${resp.body.status}'`;
    }
    return Promise.reject(new Error(errmsg));
  }

  function transformError(e) {
    let err = e;
    if (err.urn) {
      err = new Error(`[acme-v2] ${auth.altname} status:${e.status} ${e.detail}`);
      err.auth = auth;
      err.altname = auth.altname;
      err.type = auth.type;
      err.code = e.status === "invalid" ? "E_ACME_CHALLENGE" : "E_ACME_UNKNOWN";
    }
    throw err;
  }

  function respondToChallenge() {
    return U._jwsRequest(me, {
      accountKey: options.accountKey,
      url: auth.url,
      protected: { kid },
      payload: Enc.strToBuf(JSON.stringify({})),
    })
      .then(checkResult)
      .catch(transformError);
  }

  return respondToChallenge();
};

export function validateCsr(csrPem, domainSuffix) {
  if (typeof csrPem !== "string" || Buffer.byteLength(csrPem, "utf8") > maxBodyBytes) {
    throw Object.assign(new Error("CSR must be a string no larger than 16 KB"), { statusCode: 400 });
  }

  let csrDer;
  const pemMatch = csrPem.match(
    /-----BEGIN CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE REQUEST-----/,
  );
  if (pemMatch) {
    try {
      csrDer = Buffer.from(pemMatch[1].replace(/\s/g, ""), "base64");
    } catch {
      throw Object.assign(new Error("CSR is not valid base64"), { statusCode: 400 });
    }
  } else {
    try {
      csrDer = Buffer.from(csrPem.trim().replace(/\s/g, ""), "base64");
    } catch {
      throw Object.assign(new Error("CSR is not valid base64"), { statusCode: 400 });
    }
  }

  const parsed = asn1js.fromBER(toArrayBuffer(csrDer));
  if (parsed.offset === -1 || parsed.offset !== csrDer.length ||
      !(parsed.result instanceof asn1js.Sequence)) {
    throw Object.assign(new Error("CSR ASN.1 is invalid"), { statusCode: 400 });
  }
  const outer = parsed.result.valueBlock.value;
  if (outer.length !== 3 ||
      !(outer[0] instanceof asn1js.Sequence) ||
      !(outer[1] instanceof asn1js.Sequence) ||
      !(outer[2] instanceof asn1js.BitString) ||
      outer[2].valueBlock.unusedBits !== 0) {
    throw Object.assign(new Error("CSR structure is invalid"), { statusCode: 400 });
  }

  const requestInfo = outer[0];
  const requestFields = requestInfo.valueBlock.value;
  if (requestFields.length !== 4 || requestFields[0].valueBlock.valueDec !== 0) {
    throw Object.assign(new Error("CSR fields are invalid"), { statusCode: 400 });
  }

  const signatureAlgorithm = outer[1].valueBlock.value;
  if (signatureAlgorithm.length < 1 ||
      signatureAlgorithm[0].valueBlock.toString() !== "1.2.840.10045.4.3.2") {
    throw Object.assign(new Error("CSR must use ECDSA with SHA-256"), { statusCode: 400 });
  }

  const spkiDer = Buffer.from(requestFields[2].toBER(false));
  let publicKey;
  try {
    publicKey = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  } catch {
    throw Object.assign(new Error("CSR public key is invalid"), { statusCode: 400 });
  }
  if (publicKey.asymmetricKeyType !== "ec" ||
      publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw Object.assign(new Error("Only P-256 EC keys are accepted"), { statusCode: 400 });
  }

  const fingerprint = createHash("sha256").update(spkiDer).digest("hex");
  const expectedName32 = `${fingerprint.slice(0, 32)}.${domainSuffix}`;
  const expectedName16 = `${fingerprint.slice(0, 16)}.${domainSuffix}`;
  const commonName = readCommonName(requestFields[1]);
  const dnsNames = readDnsNames(requestFields[3]);
  const signature = Buffer.from(outer[2].valueBlock.valueHexView);

  const matchedName = [expectedName16, expectedName32].find(
    (name) => commonName === name && dnsNames.length === 1 && dnsNames[0] === name
  );

  if (!matchedName) {
    throw Object.assign(new Error("CSR name must match the P-256 public-key fingerprint"), { statusCode: 400 });
  }
  if (!verify("sha256", Buffer.from(requestInfo.toBER(false)), publicKey, signature)) {
    throw Object.assign(new Error("CSR signature is invalid"), { statusCode: 400 });
  }

  return { fingerprint, hostname: matchedName, csrDer, spkiDer };
}

function readCommonName(subject) {
  if (!(subject instanceof asn1js.Sequence)) {
    return undefined;
  }
  for (const relativeName of subject.valueBlock.value) {
    if (!(relativeName instanceof asn1js.Set)) {
      continue;
    }
    for (const attribute of relativeName.valueBlock.value) {
      const fields = attribute.valueBlock?.value;
      if (fields?.length === 2 && fields[0].valueBlock.toString() === "2.5.4.3") {
        return fields[1].valueBlock.value;
      }
    }
  }
  return undefined;
}

function toArrayBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function readDnsNames(attributes) {
  if (!(attributes instanceof asn1js.Constructed) ||
      attributes.idBlock.tagClass !== 3 ||
      attributes.idBlock.tagNumber !== 0) {
    return [];
  }

  const names = [];
  for (const attribute of attributes.valueBlock.value) {
    const fields = attribute.valueBlock?.value;
    if (fields?.length !== 2 ||
        fields[0].valueBlock.toString() !== "1.2.840.113549.1.9.14") {
      continue;
    }
    for (const extension of fields[1].valueBlock.value[0]?.valueBlock?.value ?? []) {
      const extensionFields = extension.valueBlock?.value;
      if (extensionFields?.[0]?.valueBlock.toString() !== "2.5.29.17") {
        continue;
      }
      const sanDer = extensionFields[extensionFields.length - 1].valueBlock.valueHexView;
      const parsedSan = asn1js.fromBER(toArrayBuffer(sanDer));
      if (parsedSan.offset === -1 || !(parsedSan.result instanceof asn1js.Sequence)) {
        return [];
      }
      for (const generalName of parsedSan.result.valueBlock.value) {
        if (generalName.idBlock.tagClass === 3 && generalName.idBlock.tagNumber === 2) {
          names.push(Buffer.from(generalName.valueBlock.valueHexView).toString("ascii"));
        }
      }
    }
  }
  return names;
}

function readConfig(env) {
  const required = [
    "ACME_EMAIL",
    "CF_DNS_API_TOKEN",
    "CF_ZONE_NAME",
    "CF_ZONE_ID",
    "DOMAIN_SUFFIX",
  ];
  const missing = required.filter((key) => !env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  const domainSuffix = env.DOMAIN_SUFFIX.toLowerCase().replace(/\.$/, "");
  const cfZoneName = env.CF_ZONE_NAME.toLowerCase().replace(/\.$/, "");
  const validDnsName = (name) => name.split(".").every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
  );
  if (!validDnsName(domainSuffix) || !validDnsName(cfZoneName) ||
      (domainSuffix !== cfZoneName && !domainSuffix.endsWith(`.${cfZoneName}`))) {
    throw new Error("DOMAIN_SUFFIX must be a DNS suffix such as car.tesla-droid.app");
  }

  const port = Number(env.PORT || 8080);
  const maxRequests = Number(env.MAX_REQUESTS_PER_HOUR || maxRequestsPerWindow);
  const maxCertificates = Number(env.MAX_CERTIFICATES_PER_WEEK || maxCertificatesPerWeek);
  const trustProxy = env.TRUST_PROXY === "true";
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 ||
      !Number.isSafeInteger(maxRequests) || maxRequests < 1 ||
      !Number.isSafeInteger(maxCertificates) || maxCertificates < 1 || maxCertificates > 50 ||
      (env.TRUST_PROXY !== undefined && env.TRUST_PROXY !== "true" && env.TRUST_PROXY !== "false")) {
    throw new Error("PORT and request/certificate limits must be positive integers; the weekly certificate limit cannot exceed 50; TRUST_PROXY must be true or false");
  }

  return {
    acmeEmail: env.ACME_EMAIL,
    acmeDirectoryUrl: env.ACME_DIRECTORY_URL || defaultDirectoryUrl,
    cfDnsApiToken: env.CF_DNS_API_TOKEN,
    cfZoneId: env.CF_ZONE_ID,
    cfZoneName,
    domainSuffix,
    host: env.HOST || "0.0.0.0",
    port,
    stateDirectory: resolve(env.STATE_DIR || defaultStateDirectory),
    maxRequestsPerWindow: maxRequests,
    maxCertificatesPerWeek: maxCertificates,
    trustProxy,
  };
}

async function cloudflareRequest(config, method, path, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${config.cfDnsApiToken}`,
      "Content-Type": "application/json",
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const result = await response.json();
  if (!response.ok || !result.success) {
    const errorDetails = result.errors?.map((e) => `${e.code}: ${e.message}`).join(", ") || response.statusText;
    throw new Error(`Cloudflare DNS request failed with HTTP ${response.status}: ${errorDetails}`);
  }
  return result.result;
}

async function waitForTxtRecord(name, value) {
  const deadline = Date.now() + 6_000;
  let lastError;
  const resolver = new Resolver();
  resolver.setServers(["1.1.1.1", "1.0.0.1"]);

  let cfOk = false;
  while (Date.now() < deadline) {
    try {
      const records = await resolver.resolveTxt(name);
      if (records.some((chunks) => chunks.join("") === value)) {
        cfOk = true;
        break;
      }
    } catch (error) {
      lastError = error;
    }
    await delay(1_000);
  }
  if (!cfOk) {
    throw new Error(`DNS challenge record was not visible within deadline${lastError ? `: ${lastError.code || lastError.message}` : ""}`);
  }
}

let accountKeyPromise;
let issuanceQueue = Promise.resolve();

function serializeIssuance(operation) {
  const result = issuanceQueue.then(operation, operation);
  issuanceQueue = result.catch(() => {});
  return result;
}

async function writeJsonAtomically(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, JSON.stringify(value), { mode: 0o600, flag: "wx" });
  await rename(temporaryPath, path);
}

async function readCachedCertificate(config, hostname, fingerprint) {
  const cachePath = resolve(config.stateDirectory, "certificates", `${fingerprint}.json`);
  let cached;
  try {
    cached = JSON.parse(await readFile(cachePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }

  if (cached.name !== hostname || typeof cached.cert !== "string" ||
      !Number.isSafeInteger(cached.expires_at)) {
    throw new Error("Cached certificate record is malformed");
  }
  const certificate = new X509Certificate(cached.cert);
  if (!certificate.issuer.includes("Let's Encrypt")) {
    log(`Discarding non-Let's Encrypt cached certificate for ${hostname} (issuer: ${certificate.issuer})`);
    return null;
  }
  if (!certificate.checkHost(hostname) ||
      Math.floor(Date.parse(certificate.validTo) / 1000) !== cached.expires_at) {
    throw new Error("Cached certificate does not match its device identity");
  }
  return cached;
}

export async function loadOrCreateAccountKey(stateDirectory) {
  const keyPath = resolve(stateDirectory, "acme-account-key.json");
  await mkdir(dirname(keyPath), { recursive: true });
  try {
    return JSON.parse(await readFile(keyPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  if (!accountKeyPromise) {
    accountKeyPromise = (async () => {
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const accountKey = privateKey.export({ format: "jwk" });
      try {
        await writeFile(keyPath, JSON.stringify(accountKey), { mode: 0o600, flag: "wx" });
        return accountKey;
      } catch (error) {
        if (error.code !== "EEXIST") {
          throw error;
        }
        return JSON.parse(await readFile(keyPath, "utf8"));
      }
    })();
  }
  try {
    return await readFile(keyPath, "utf8").then((json) => JSON.parse(json));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
    return accountKeyPromise;
  }
}

const inFlightIssuances = new Map();

function generateFallbackCertificate(spkiDer, hostname) {
  const caKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const notBefore = new Date();
  const notAfter = new Date(Date.now() + 90 * 24 * 3600 * 1000);

  const sanExtension = new asn1js.Sequence({
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

  const tbs = new asn1js.Sequence({
    value: [
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1js.Integer({ value: 2 })] }),
      new asn1js.Integer({ value: Math.floor(Date.now() / 1000) }),
      new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "1.2.840.10045.4.3.2" })] }),
      new asn1js.Sequence({
        value: [
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                  new asn1js.Utf8String({ value: "TeslaDroid Authority" }),
                ],
              }),
            ],
          }),
        ],
      }),
      new asn1js.Sequence({
        value: [
          new asn1js.UTCTime({ valueDate: notBefore }),
          new asn1js.UTCTime({ valueDate: notAfter }),
        ],
      }),
      new asn1js.Sequence({
        value: [
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                  new asn1js.Utf8String({ value: hostname }),
                ],
              }),
            ],
          }),
        ],
      }),
      asn1js.fromBER(toArrayBuffer(spkiDer)).result,
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 3 }, value: [new asn1js.Sequence({ value: [sanExtension] })] }),
    ],
  });

  const tbsDer = Buffer.from(tbs.toBER(false));
  const sig = sign("sha256", tbsDer, caKey.privateKey);

  const certSeq = new asn1js.Sequence({
    value: [
      tbs,
      new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "1.2.840.10045.4.3.2" })] }),
      new asn1js.BitString({ valueHex: toArrayBuffer(sig) }),
    ],
  });

  const certDer = Buffer.from(certSeq.toBER(false));
  const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  const expiresAt = Math.floor(notAfter.getTime() / 1000);

  return {
    cert: certPem,
    name: hostname,
    expires_at: expiresAt,
  };
}

async function requestCertificate(config, csrPem) {
  const identity = validateCsr(csrPem, config.domainSuffix);
  return serializeIssuance(async () => {
    const cached = await readCachedCertificate(config, identity.hostname, identity.fingerprint);
    const now = Date.now();
    if (cached && cached.expires_at * 1000 > now + 14 * 24 * 60 * 60 * 1000) {
      return cached;
    }

    const quotaPath = resolve(config.stateDirectory, "issuance-history.json");
    let history;
    try {
      history = JSON.parse(await readFile(quotaPath, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      history = [];
    }
    if (!Array.isArray(history) || history.some((entry) => !Number.isSafeInteger(entry))) {
      throw new Error("Certificate issuance history is malformed");
    }
    history = history.filter((timestamp) => now - timestamp < certificateLimitWindowMs);
    if (history.length >= config.maxCertificatesPerWeek) {
      throw Object.assign(new Error("The configured weekly certificate limit has been reached"), {
        statusCode: 429,
      });
    }

    let issuancePromise = inFlightIssuances.get(identity.fingerprint);
    if (!issuancePromise) {
      history.push(now);
      await writeJsonAtomically(quotaPath, history);

      issuancePromise = issueNewCertificate(config, identity.csrDer, identity.hostname)
        .then(async (acmeCert) => {
          const cachePath = resolve(config.stateDirectory, "certificates", `${identity.fingerprint}.json`);
          await writeJsonAtomically(cachePath, acmeCert);
          log(`Let's Encrypt certificate cached for ${identity.hostname}`);
          return acmeCert;
        })
        .catch(async (e) => {
          try {
            history.pop();
            await writeJsonAtomically(quotaPath, history);
          } catch {}
          log(`Let's Encrypt issuance failed for ${identity.hostname}: ${e.message}`);
          throw e;
        })
        .finally(() => {
          inFlightIssuances.delete(identity.fingerprint);
        });
      inFlightIssuances.set(identity.fingerprint, issuancePromise);
    }

    const issued = await issuancePromise;
    return issued;
  });
}

async function issueNewCertificate(config, csrDer, hostname) {
  const accountKey = await loadOrCreateAccountKey(config.stateDirectory);
  const acme = ACME.create({
    maintainerEmail: config.acmeEmail,
    packageAgent: `tesla-droid-cert-issuer/${issuerVersion}`,
    notify: (event, details) => {
      if (event === "error" || event === "warning") {
        console.error(`ACME ${event}:`, details?.message || "see ACME event details");
      }
    },
  });
  await acme.init(config.acmeDirectoryUrl);
  const account = await acme.accounts.create({
    subscriberEmail: config.acmeEmail,
    agreeToTerms: true,
    accountKey,
  });

  const challenge = createDns01Challenge(config);
  const certificateOptions = {
    account,
    accountKey,
    csr: csrDer,
    domains: [hostname],
    challenges: { "dns-01": challenge },
  };
  const pems = await acme.certificates.create(certificateOptions);
  const certificatePem = `${pems.cert.trim()}\n${pems.chain.trim()}\n`;
  const certificate = new X509Certificate(certificatePem);
  const expiresAt = Math.floor(Date.parse(certificate.validTo) / 1000);
  if (!Number.isFinite(expiresAt)) {
    throw new Error("Certificate authority returned an unreadable certificate expiry");
  }
  return {
    cert: certificatePem,
    name: hostname,
    expires_at: expiresAt,
  };
}

function isOrderNotReadyError(error) {
  return /urn:ietf:params:acme:error:orderNotReady/i.test(
    `${error.detail || ""} ${error.message || ""}`,
  );
}

export async function retryOrderNotReady(operation, wait = delay) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      const retryDelay = orderNotReadyRetryDelaysMs[attempt];
      if (!retryDelay || !isOrderNotReadyError(error)) {
        throw error;
      }
      await wait(retryDelay);
    }
  }
}

function createDns01Challenge(config) {
  const recordIds = new Map();
  return {
    init: async () => {},
    zones: async ({ challenge: { dnsHosts } }) => {
      if (dnsHosts.some((name) => !name.endsWith(`.${config.cfZoneName}`))) {
        throw new Error("ACME requested DNS validation outside the configured Cloudflare zone");
      }
      return [config.cfZoneName];
    },
    set: async ({ challenge }) => {
      const { dnsHost, keyAuthorizationDigest } = challenge;
      const record = await cloudflareRequest(config, "POST", `/zones/${config.cfZoneId}/dns_records`, {
        type: "TXT",
        name: dnsHost,
        content: keyAuthorizationDigest,
        ttl: 120,
      });
      const mapKey = `${dnsHost}:${keyAuthorizationDigest}`;
      recordIds.set(mapKey, record.id);
      try {
        await waitForTxtRecord(dnsHost, keyAuthorizationDigest);
      } catch (error) {
        await cloudflareRequest(config, "DELETE", `/zones/${config.cfZoneId}/dns_records/${record.id}`);
        recordIds.delete(mapKey);
        throw error;
      }
    },
    get: async ({ challenge }) => {
      const { dnsHost, keyAuthorizationDigest } = challenge;
      const query = new URLSearchParams({
        type: "TXT",
        name: dnsHost,
        content: keyAuthorizationDigest,
      });
      const records = await cloudflareRequest(
        config,
        "GET",
        `/zones/${config.cfZoneId}/dns_records?${query}`,
      );
      return records.some((record) => record.content === keyAuthorizationDigest)
        ? { dnsAuthorization: keyAuthorizationDigest }
        : null;
    },
    remove: async ({ challenge }) => {
      const { dnsHost, keyAuthorizationDigest } = challenge;
      const mapKey = `${dnsHost}:${keyAuthorizationDigest}`;
      const recordId = recordIds.get(mapKey);
      if (recordId) {
        recordIds.delete(mapKey);
        delay(300_000).then(() => {
          cloudflareRequest(
            config,
            "DELETE",
            `/zones/${config.cfZoneId}/dns_records/${recordId}`,
          ).catch((e) => console.error("Delayed DNS record cleanup warning:", e.message));
        });
      }
    },
  };
}

function readJson(request) {
  return new Promise((resolveBody, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      if (body === null) {
        return;
      }
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > maxBodyBytes) {
        body = null;
      }
    });
    request.on("end", () => {
      if (body === null) {
        reject(Object.assign(new Error("Request body too large"), { statusCode: 413 }));
        return;
      }
      try {
        resolveBody(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON"), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

export function createIssuerServer({ config, issueCertificate = (csr) => requestCertificate(config, csr) }) {
  const requestTimes = new Map();
  let activeIssuances = 0;

  return createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      sendJson(response, 200, { status: "ok" });
      return;
    }
    if (request.method === "POST" && request.url === "/v1/init-dns") {
      try {
        const results = await ensureInfrastructureDns(config);
        sendJson(response, 200, { status: "dns_configured", results });
      } catch (err) {
        sendJson(response, 500, { error: err.message });
      }
      return;
    }
    if (request.method === "POST" && request.url === "/v1/clean-txt") {
      try {
        const records = await cloudflareRequest(config, "GET", `/zones/${config.cfZoneId}/dns_records?type=TXT&per_page=100`);
        const deleted = [];
        for (const r of records) {
          if (r.name.startsWith("_acme-challenge.") || r.name.startsWith("_greenlock")) {
            await cloudflareRequest(config, "DELETE", `/zones/${config.cfZoneId}/dns_records/${r.id}`);
            deleted.push(r.name);
          }
        }
        sendJson(response, 200, { status: "cleaned", count: deleted.length, deleted });
      } catch (err) {
        sendJson(response, 500, { error: err.message });
      }
      return;
    }
    if (request.method === "GET" && request.url === "/v1/logs") {
      sendJson(response, 200, { logs: memoryLogs });
      return;
    }
    if (request.method === "POST" && request.url === "/v1/issue-wildcard") {
      try {
        log("Received request for wildcard certificate issuance");
        const CSR = require("@root/csr");
        const Keypairs = require("@root/keypairs");
        const pair = await Keypairs.generate({ kty: "EC", format: "jwk" });
        const csrDer = await CSR.csr({
          jwk: pair.private,
          domains: [`*.${config.domainSuffix}`],
          encoding: "der",
        });
        const issued = await issueNewCertificate(config, csrDer, `*.${config.domainSuffix}`);
        sendJson(response, 200, {
          cert: issued.cert,
          name: issued.name,
          expires_at: issued.expires_at,
          privateKey: pair.private,
        });
      } catch (err) {
        log("Wildcard issuance error:", err.message);
        sendJson(response, 500, { error: err.message, stack: err.stack });
      }
      return;
    }
    if (request.method === "GET" && request.url === "/v1/challenge") {
      const nonce = randomUUID().replace(/-/g, "");
      sendJson(response, 200, { nonce });
      return;
    }
    if (request.method === "POST" && request.url === "/v1/status") {
      sendJson(response, 200, { ok: true, status: "ok" });
      return;
    }
    const isIssueRoute = request.method === "POST" && (
      request.url === "/v1/issue" ||
      request.url === "/v1/enroll" ||
      request.url === "/v1/refresh"
    );
    if (!isIssueRoute) {
      sendJson(response, 404, { error: "not_found" });
      return;
    }
    if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
      sendJson(response, 415, { error: "content_type_must_be_json" });
      return;
    }

    const forwardedFor = config.trustProxy ? request.headers["x-forwarded-for"] : undefined;
    const forwardedClientIp = (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor)
      ?.split(",")[0]?.trim();
    const clientIp = forwardedClientIp || request.socket.remoteAddress || "unknown";
    const now = Date.now();
    const recent = (requestTimes.get(clientIp) || []).filter((time) => now - time < rateLimitWindowMs);
    if (recent.length >= config.maxRequestsPerWindow) {
      sendJson(response, 429, { error: "rate_limit_exceeded" });
      return;
    }
    recent.push(now);
    requestTimes.set(clientIp, recent);
    if (requestTimes.size > 5000) {
      for (const [ip, times] of requestTimes) {
        const unexpired = times.filter((time) => now - time < rateLimitWindowMs);
        if (unexpired.length) {
          requestTimes.set(ip, unexpired);
        } else {
          requestTimes.delete(ip);
        }
      }
    }

    try {
      const body = await readJson(request);
      if (!body || typeof body.csr !== "string") {
        sendJson(response, 400, { error: "expected_csr_pem" });
        return;
      }
      if (activeIssuances >= 2) {
        sendJson(response, 503, { error: "issuer_busy" });
        return;
      }
      try {
        validateCsr(body.csr, config.domainSuffix);
      } catch (error) {
        error.statusCode ||= 400;
        throw error;
      }
      activeIssuances += 1;
      try {
        const issued = await issueCertificate(body.csr);
        sendJson(response, 200, issued);
      } finally {
        activeIssuances -= 1;
      }
    } catch (error) {
      const statusCode = error.statusCode || 502;
      if (statusCode >= 500) {
        console.error("Certificate issuance failed:", error.stack || error.message);
      } else if (statusCode === 400) {
        console.warn("CSR validation failed:", error.message);
      }
      sendJson(response, statusCode, {
        error: statusCode === 413
          ? "request_too_large"
          : statusCode === 400
            ? "invalid_csr"
            : statusCode === 429
              ? "rate_limit_exceeded"
              : "certificate_issuance_failed",
        ...(statusCode >= 500 && error.message ? { detail: error.message } : {}),
      });
    }
  });
}

export async function ensureInfrastructureDns(config) {
  if (!config.cfZoneId || !config.cfDnsApiToken) {
    return { skipped: "no_cf_credentials" };
  }
  const zone = await cloudflareRequest(config, "GET", `/zones/${config.cfZoneId}`).catch((e) => ({ error: e.message }));
  const records = await cloudflareRequest(config, "GET", `/zones/${config.cfZoneId}/dns_records?per_page=100`);
  const dnssec = await cloudflareRequest(config, "GET", `/zones/${config.cfZoneId}/dnssec`).catch((e) => ({ error: e.message }));
  const actions = [];

  const wildcardName = `*.${config.domainSuffix}`;
  const hasWildcard = records.some((r) => r.type === "A" && (r.name === wildcardName || r.name === `*.car`));
  if (!hasWildcard) {
    actions.push(`Created wildcard ${wildcardName} -> 100.99.9.9`);
    await cloudflareRequest(config, "POST", `/zones/${config.cfZoneId}/dns_records`, {
      type: "A",
      name: wildcardName,
      content: "100.99.9.9",
      ttl: 120,
      proxied: false,
    });
  }

  const hasBase = records.some((r) => r.type === "A" && r.name === config.domainSuffix);
  if (!hasBase) {
    actions.push(`Created base ${config.domainSuffix} -> 100.99.9.9`);
    await cloudflareRequest(config, "POST", `/zones/${config.cfZoneId}/dns_records`, {
      type: "A",
      name: config.domainSuffix,
      content: "100.99.9.9",
      ttl: 120,
      proxied: false,
    });
  }

  const hasCaa = records.some((r) => r.type === "CAA" && r.data?.value?.includes("letsencrypt.org"));
  if (!hasCaa) {
    actions.push(`Created CAA for ${config.cfZoneName} -> letsencrypt.org`);
    await cloudflareRequest(config, "POST", `/zones/${config.cfZoneId}/dns_records`, {
      type: "CAA",
      name: config.cfZoneName,
      data: {
        flags: 0,
        tag: "issue",
        value: "letsencrypt.org",
      },
      ttl: 120,
    });
  }

  return {
    actions,
    zone: zone ? { status: zone.status, name_servers: zone.name_servers, original_registrar: zone.original_registrar, activated_on: zone.activated_on } : null,
    dnssec,
    existing: records.map((r) => ({ name: r.name, type: r.type, content: r.content })),
  };
}

export function startServer(env = process.env) {
  const config = readConfig(env);
  const server = createIssuerServer({ config });
  server.listen(config.port, config.host, () => {
    console.log(`Certificate issuer listening on ${config.host}:${config.port}`);
    console.log(`ACME directory: ${config.acmeDirectoryUrl}`);
    console.log(`Certificate names: <public-key-fingerprint>.${config.domainSuffix}`);
    ensureInfrastructureDns(config).then((acts) => {
      if (acts.length) console.log("Infrastructure DNS configured:", acts);
    }).catch((e) => console.error("Infrastructure DNS warning:", e.message));
  });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    startServer();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

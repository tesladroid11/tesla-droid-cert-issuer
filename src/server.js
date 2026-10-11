import { createServer } from "node:http";
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, verify, X509Certificate } from "node:crypto";
import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { Resolver, resolveTxt } from "node:dns/promises";
import * as asn1js from "asn1js";
import ACME from "@root/acme";

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const defaultStateDirectory = resolve(moduleDirectory, "../data");
const stagingDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";
const maxBodyBytes = 16 * 1024;
const rateLimitWindowMs = 60 * 60 * 1000;
const certificateLimitWindowMs = 7 * 24 * 60 * 60 * 1000;
const maxRequestsPerWindow = 5;
const maxCertificatesPerWeek = 40;
const orderNotReadyRetryDelaysMs = [3000, 7000];
const issuerVersion = "0.1.0";

export function validateCsr(csrPem, domainSuffix) {
  if (typeof csrPem !== "string" || Buffer.byteLength(csrPem, "utf8") > maxBodyBytes) {
    throw Object.assign(new Error("CSR must be a PEM string no larger than 16 KB"), { statusCode: 400 });
  }

  const pemMatch = csrPem.match(
    /^\s*-----BEGIN CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE REQUEST-----\s*$/,
  );
  if (!pemMatch) {
    throw Object.assign(new Error("CSR is not valid PEM"), { statusCode: 400 });
  }

  let csrDer;
  try {
    csrDer = Buffer.from(pemMatch[1].replace(/\s/g, ""), "base64");
  } catch {
    throw Object.assign(new Error("CSR is not valid base64"), { statusCode: 400 });
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
  const expectedName = `${fingerprint.slice(0, 32)}.${domainSuffix}`;
  const commonName = readCommonName(requestFields[1]);
  const dnsNames = readDnsNames(requestFields[3]);
  const signature = Buffer.from(outer[2].valueBlock.valueHexView);

  if (commonName !== expectedName ||
      dnsNames.length !== 1 ||
      dnsNames[0] !== expectedName) {
    throw Object.assign(new Error("CSR name must match the P-256 public-key fingerprint"), { statusCode: 400 });
  }
  if (!verify("sha256", Buffer.from(requestInfo.toBER(false)), publicKey, signature)) {
    throw Object.assign(new Error("CSR signature is invalid"), { statusCode: 400 });
  }

  return { fingerprint, hostname: expectedName, csrDer };
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
    acmeDirectoryUrl: env.ACME_DIRECTORY_URL || stagingDirectoryUrl,
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
  const deadline = Date.now() + 180_000;
  let lastError;
  const resolver = new Resolver();
  resolver.setServers(["1.1.1.1", "1.0.0.1"]);
  while (Date.now() < deadline) {
    try {
      const records = await resolver.resolveTxt(name);
      if (records.some((chunks) => chunks.join("") === value)) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await delay(3_000);
  }
  throw new Error(`DNS challenge record was not visible within 180 seconds${lastError ? `: ${lastError.code || lastError.message}` : ""}`);
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
    history.push(now);
    await writeJsonAtomically(quotaPath, history);

    let issued;
    try {
      issued = await issueNewCertificate(config, identity.csrDer, identity.hostname);
    } catch (error) {
      history.pop();
      await writeJsonAtomically(quotaPath, history);
      throw error;
    }

    const cachePath = resolve(config.stateDirectory, "certificates", `${identity.fingerprint}.json`);
    await writeJsonAtomically(cachePath, issued);
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
  const pems = await retryOrderNotReady(
    () => acme.certificates.create(certificateOptions),
  );
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
        await cloudflareRequest(
          config,
          "DELETE",
          `/zones/${config.cfZoneId}/dns_records/${recordId}`,
        );
        recordIds.delete(mapKey);
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
    if (request.method !== "POST" || request.url !== "/v1/issue") {
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
      if (!body || Object.keys(body).length !== 1 || typeof body.csr !== "string") {
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

export function startServer(env = process.env) {
  const config = readConfig(env);
  const server = createIssuerServer({ config });
  server.listen(config.port, config.host, () => {
    console.log(`Certificate issuer listening on ${config.host}:${config.port}`);
    console.log(`ACME directory: ${config.acmeDirectoryUrl}`);
    console.log(`Certificate names: <public-key-fingerprint>.${config.domainSuffix}`);
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

console.log("Requesting wildcard certificate from https://issuer.tesla-droid.app/v1/issue-wildcard ...");
const startTime = Date.now();
try {
  const res = await fetch("https://issuer.tesla-droid.app/v1/issue-wildcard", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  console.log(`HTTP Status: ${res.status} (took ${Date.now() - startTime}ms)`);
  const data = await res.json();
  if (res.ok) {
    console.log("SUCCESS! Wildcard certificate issued!");
    console.log("Name:", data.name);
    console.log("Expires at:", new Date(data.expires_at * 1000).toISOString());
    console.log("Certificate PEM:", data.cert.slice(0, 100) + "...");
  } else {
    console.error("Failed:", data);
  }
} catch (err) {
  console.error("Request failed:", err);
}

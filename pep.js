// pep.js
app.post("/pep/intercept", async (req, res) => {
  const { access_token, dpop_proof, resource } = req.body;

  // Verify DPoP (htm, htu, jti, signature)
  try {
    verifyDPoP(dpop_proof, req);
  } catch (e) {
    return res.json({
      effect: "deny",
      reason: "Invalid DPoP proof"
    });
  }


  // Introspect token with Keycloak
  const tokenInfo = await introspectToken(access_token);
  if (!tokenInfo.active) {
    return res.json({ effect: "deny", reason: "Invalid token" });
  }

  // Build authorization query
  const policyRequest = {
    user: tokenInfo.sub,
    device_id: tokenInfo.device_id,
    scopes: tokenInfo.scope,
    resource
  };

  // Ask PDP
  const decision = await fetch("http://pdp:4002/pdp/evaluate", {
    method: "POST",
    body: JSON.stringify(policyRequest),
    headers: { "Content-Type": "application/json" }
  });

  const result = await decision.json();

  // Enforce
  if (result.decision === "permit") {
    return res.json({
      effect: "permit",
      forward_headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
  }

  return res.json({
    effect: "deny",
    reason: result.reason
  });
});

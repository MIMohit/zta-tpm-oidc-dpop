// decision-controller.js
app.post("/access/request", async (req, res) => {
  const ztaResponse = await fetch("http://pep:4001/pep/intercept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req.body)
  });

  const decision = await ztaResponse.json();

  if (decision.effect === "permit") {
    // route to resource server
    const resourceData = await fetch("http://resource:5001/company/info", {
      headers: decision.forward_headers
    });
    return res.json(await resourceData.json());
  }

  return res.status(403).json({
    error: "Access denied",
    reason: decision.reason
  });
});

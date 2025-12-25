async function accessAudit() {
  const res = await fetch("/access/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      resource: "company.audit",
      access_token: window.sessionStorage.getItem("access_token"),
      dpop_proof: window.sessionStorage.getItem("dpop")
    })
  });

  const data = await res.json();
  document.getElementById("result").textContent =
    JSON.stringify(data, null, 2);
}

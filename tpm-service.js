import http from "http";
import { exec } from "child_process";

http.createServer((req, res) => {
  if (req.url === "/attest") {
    exec(
      'powershell.exe -ExecutionPolicy Bypass -File "E:\\zta-tpm-oidc-dpop\\public\\generate-tpm-attestation.ps1"',
      (err, stdout, stderr) => {
        if (err) {
          res.writeHead(500);
          return res.end(stderr);
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(stdout);
      }
    );
  } else {
    res.writeHead(404);
    res.end();
  }
}).listen(9000, () => {
  console.log("🔐 Windows TPM service running on port 9000");
});

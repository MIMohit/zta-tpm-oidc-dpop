# zta-tpm-oidc-dpop

# never use the main realm (master) of the keycloak, create a new realm, named "zta-realm".

# client id = "remote-work-app"

# root url = "http://localhost:5173"

# redirect uri = "http://localhost:5173/callback"

# web-origins = "http://localhost:5173"

# client authentication - disable

# standard flow and direct access grant - enable

# pkce - S256

# for user - it's upto you. however, what credentials you use must ensure that password follows certain security protocols. and these credentials are crucial for your login. DONOT USE PLAIN PASSWORDS; IT'S TEDIOUS.
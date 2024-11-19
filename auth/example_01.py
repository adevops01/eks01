from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt
import requests

# Azure AD configurations
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
TENANT_ID = "your-tenant-id"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"

# OAuth2 Bearer
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{AUTHORITY}/oauth2/v2.0/authorize",
    tokenUrl=TOKEN_URL
)

# FastAPI instance
app = FastAPI()

# Fetch JWKS
jwks = requests.get(JWKS_URL).json()

def verify_token(token: str):
    try:
        # Decode the JWT
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=AUTHORITY
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTClaimsError:
        raise HTTPException(status_code=401, detail="Invalid claims")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/secure-data")
def secure_data(token: str = Depends(oauth2_scheme)):
    user = verify_token(token)
    return {"message": "Secure data", "user": user}

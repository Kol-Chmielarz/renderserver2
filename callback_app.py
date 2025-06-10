from fastapi import FastAPI, Request
import httpx, base64, json, os
from cryptography.fernet import Fernet

app = FastAPI()

# Render will set these in Environment
CLIENT_ID      = os.getenv("CLIENT_ID")
CLIENT_SECRET  = os.getenv("CLIENT_SECRET")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
# PUBLIC_CALLBACK must match your Render URL + "/callback"
REDIRECT_URI   = os.getenv("PUBLIC_CALLBACK")  
TOKEN_URL      = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
fernet         = Fernet(ENCRYPTION_KEY.encode())

@app.get("/callback")
async def qbo_callback(request: Request):
    code     = request.query_params.get("code")
    realm_id = request.query_params.get("realmId")
    if not code or not realm_id:
        return {"error": "Missing code or realmId"}

    creds_b64 = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers   = {
        "Authorization": f"Basic {creds_b64}",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    token_resp = await httpx.AsyncClient().post(TOKEN_URL, data=data, headers=headers)
    token = token_resp.json()

    # write encrypted tokens.json
    json.dump(
        {
            "access_token":  fernet.encrypt(token["access_token"].encode()).decode(),
            "refresh_token": fernet.encrypt(token["refresh_token"].encode()).decode(),
            "realm_id": realm_id,
        },
        open("tokens.json", "w"),
    )
    return {"status": "Tokens saved. You can now download via /export."}

@app.get("/export")
def export_tokens():
    from fastapi.responses import FileResponse
    return FileResponse("tokens.json", media_type="application/json", filename="tokens.json")
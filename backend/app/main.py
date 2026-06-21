from http.client import responses
from fastapi import FastAPI
import httpx

app = FastAPI()

@app.get("/scan")
async def run_scan(url : str):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(url , timeout = 10 )

    headers = response.headers
    return {
        "url" : response.url ,
        "has_hsts" : "strict-transport-security" in headers,

    }
print(responses)
        

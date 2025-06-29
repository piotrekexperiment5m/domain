from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import re
import httpx

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def resolve_txt(domain: str):
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            url = f"https://dns.google/resolve?name={domain}&type=TXT"
            resp = await client.get(url)
            data = resp.json()
            return [r["data"].strip('"') for r in data.get("Answer", []) if "data" in r]
    except Exception as e:
        return []

async def get_spf(domain: str):
    records = await resolve_txt(domain)
    for txt in records:
        if txt.startswith("v=spf1"):
            return {
                "found": True,
                "raw": txt,
                "parsed": {
                    "include": re.findall(r'include:([\w\.-]+)', txt),
                    "ip4": re.findall(r'ip4:([\d./]+)', txt),
                    "ip6": re.findall(r'ip6:([\w:]+)', txt),
                    "all": re.findall(r'([-~+]?all)', txt)
                }
            }
    return {"found": False}

async def get_dmarc(domain: str):
    records = await resolve_txt(f"_dmarc.{domain}")
    for txt in records:
        if txt.startswith("v=DMARC1"):
            return {
                "found": True,
                "raw": txt,
                "policy": re.findall(r"p=([a-zA-Z]+)", txt)[0] if "p=" in txt else None,
                "rua": re.findall(r"rua=mailto:([^;]+)", txt)[0] if "rua=" in txt else None
            }
    return {"found": False}

async def get_dkim(domain: str, selector="default"):
    records = await resolve_txt(f"{selector}._domainkey.{domain}")
    for txt in records:
        if txt.startswith("v=DKIM1"):
            return {
                "found": True,
                "raw": txt,
                "key_prefix": (re.findall(r"p=([^;]+)", txt)[0][:30] + "...") if "p=" in txt else None
            }
    return {"found": False}

@app.get("/")
async def root():
    return {"status": "ok", "message": "Use /check?domain=..."}

@app.get("/check")
async def check(domain: str):
    try:
        spf = await get_spf(domain)
        dmarc = await get_dmarc(domain)
        dkim = await get_dkim(domain)
        return {
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim
        }
    except Exception as e:
        return {"error": str(e)}

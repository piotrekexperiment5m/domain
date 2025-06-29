from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import dns.resolver
import ssl, socket
import re

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_txt_record(domain, prefix=""):
    try:
        name = f"{prefix}.{domain}" if prefix else domain
        result = dns.resolver.resolve(name, "TXT")
        return ["".join(r.strings[0].decode() if isinstance(r.strings[0], bytes) else r.strings[0] for r in result)]
    except:
        return []

def get_spf(domain):
    records = get_txt_record(domain)
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

def get_dmarc(domain):
    records = get_txt_record(domain, "_dmarc")
    for txt in records:
        if txt.startswith("v=DMARC1"):
            return {
                "found": True,
                "raw": txt,
                "policy": re.findall(r"p=([a-zA-Z]+)", txt)[0] if "p=" in txt else None,
                "rua": re.findall(r"rua=mailto:([^;]+)", txt)[0] if "rua=" in txt else None
            }
    return {"found": False}

def get_dkim(domain, selectors=["default", "mail", "google", "k1"]):
    results = {}
    for sel in selectors:
        records = get_txt_record(domain, f"{sel}._domainkey")
        if records:
            txt = records[0]
            results[sel] = {
                "found": True,
                "raw": txt,
                "key_prefix": (re.findall(r"p=([^;]+)", txt)[0][:30] + "...") if "p=" in txt else None
            }
        else:
            results[sel] = {"found": False}
    return {"records": results, "selectors_checked": selectors}

def get_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer")
                }
    except Exception as e:
        return {"error": str(e)}

@app.get("/check")
async def check_domain(domain: str):
    try:
        return {
            "domain": domain,
            "spf": get_spf(domain),
            "dkim": get_dkim(domain),
            "dmarc": get_dmarc(domain),
            "ssl": "skipped"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
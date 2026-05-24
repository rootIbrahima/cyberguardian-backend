from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import scans

app = FastAPI(title="API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)


@app.get("/")
def root():
    return {"status": "ok", "service": "CyberGuardian API"}

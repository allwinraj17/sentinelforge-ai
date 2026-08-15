from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app import models
from app.scanner import extract_zip_to_temp, run_semgrep_scan, cleanup_temp

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelForge AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "SentinelForge AI backend is running", "environment": settings.environment}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    contents = await file.read()
    extract_dir = extract_zip_to_temp(contents)

    try:
        findings = run_semgrep_scan(extract_dir)
        return {
            "filename": file.filename,
            "findings_count": len(findings),
            "findings": findings,
        }
    finally:
        cleanup_temp(extract_dir)
from fastapi import FastAPI

app = FastAPI(title="SentinelForge AI")

@app.get("/")
def read_root():
    return {"message": "SentinelForge AI backend is running"}

@app.get("/health")
def health_check():
    return {"status": "ok"}
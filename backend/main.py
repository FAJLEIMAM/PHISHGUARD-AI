import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.api.routes import router
from pathlib import Path

app = FastAPI(title="PhishGuard AI X")
# Serve static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Serve index.html at root
@app.get("/")
async def serve_frontend():
    return FileResponse(Path("frontend/index.html"))

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Get project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Path to frontend folder
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Serve static files from frontend folder
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# Serve index.html
@app.get("/")
def serve_frontend():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

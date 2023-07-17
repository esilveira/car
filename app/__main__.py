from app.main import create_app
import uvicorn
import logging

app = create_app()
logging.basicConfig()
uvicorn.run(
    "app.main:create_app",
    host="0.0.0.0",
    port=8000,
    reload=True,
    factory=True
)

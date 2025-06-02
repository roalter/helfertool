# server.py

import os

import django
import uvicorn

django.setup()
base = os.path.dirname(__file__)

if __name__ == "__main__":
    uvicorn.run(
        "helfertool.asgi:application",
        app_dir=base,
        host="0.0.0.0",
        port=8193,
        workers=3,
        lifespan="off",
        proxy_headers=True,
        date_header=True,
        server_header=True,
    )

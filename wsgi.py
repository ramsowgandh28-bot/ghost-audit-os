"""WSGI entry point for Ghost Audit OS production deployment (Gunicorn / Render)."""
import os
import sys

root_dir = os.path.dirname(os.path.abspath(__file__))
code_dir = os.path.join(root_dir, "code")
web_dir = os.path.join(root_dir, "web")

for d in [root_dir, code_dir, web_dir]:
    if d not in sys.path:
        sys.path.insert(0, d)

from web.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

DIST_DIR = Path(__file__).resolve().parent / "dist"

router = APIRouter(tags=["Frontend Dashboard"])
bp = router  # Backward compatibility alias


@router.get("/favicon.svg", include_in_schema=False)
async def serve_favicon():
    fav = DIST_DIR / "favicon.svg"
    if fav.is_file():
        return FileResponse(fav, headers={"Cache-Control": "public, max-age=86400"})
    return HTMLResponse("", status_code=404)


@router.get("/icons.svg", include_in_schema=False)
async def serve_icons():
    icons = DIST_DIR / "icons.svg"
    if icons.is_file():
        return FileResponse(icons, headers={"Cache-Control": "public, max-age=86400"})
    return HTMLResponse("", status_code=404)


ASSET_EXTENSIONS = {
    ".js", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", 
    ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp"
}


@router.get("/dashboard", include_in_schema=False)
@router.get("/dashboard/", include_in_schema=False)
@router.get("/dashboard/{path:path}", include_in_schema=False)
@router.get("/assets/{path:path}", include_in_schema=False)
async def serve_dashboard(path: str = ""):
    if DIST_DIR.is_dir():
        clean_path = path.strip("/")
        suffix = Path(clean_path).suffix.lower()
        is_asset = (
            "assets/" in clean_path
            or clean_path.startswith("assets")
            or suffix in ASSET_EXTENSIONS
        )

        if clean_path:
            # 1. Direct path in DIST_DIR (e.g. dist/assets/index-xxx.js or dist/favicon.svg)
            file_path = DIST_DIR / clean_path
            if file_path.is_file():
                headers = {}
                if is_asset:
                    headers["Cache-Control"] = "public, max-age=31536000, immutable"
                return FileResponse(file_path, headers=headers)

            # 2. Subpath under dist/assets/ (e.g. requested via /assets/{filename})
            asset_file = DIST_DIR / "assets" / clean_path
            if asset_file.is_file():
                return FileResponse(asset_file, headers={"Cache-Control": "public, max-age=31536000, immutable"})

            # If an asset was explicitly requested but does not exist, return 404 immediately.
            # NEVER fall through to index.html for stylesheets, scripts, or images.
            if is_asset:
                return HTMLResponse(
                    content="Asset not found",
                    status_code=404,
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
                )

        # 3. SPA Route Navigation -> Serve index.html
        index_file = DIST_DIR / "index.html"
        if index_file.is_file():
            return FileResponse(index_file, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

    return HTMLResponse(
        content=(
            "<!doctype html>"
            "<html>"
            "<head><title>InsiEDR Threat Defense Center</title></head>"
            "<body style='font-family:system-ui,-apple-system,sans-serif;padding:48px;background:#f8fafc;color:#0f172a;'>"
            "<div style='max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;padding:32px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.05);'>"
            "<h2 style='margin-top:0;color:#0b1329;'>InsiEDR Threat Defense Center</h2>"
            "<p style='color:#64748b;font-size:14px;line-height:1.6;'>The production React + TypeScript frontend assets have not yet been built in this environment.</p>"
            "<p style='font-size:13px;color:#334155;background:#f1f5f9;padding:12px;border-radius:6px;font-family:monospace;'>cd frontend && npm install && npm run build</p>"
            "</div>"
            "</body>"
            "</html>"
        ),
        status_code=503,
    )


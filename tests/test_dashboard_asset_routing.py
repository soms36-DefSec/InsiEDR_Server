from fastapi import FastAPI
from fastapi.testclient import TestClient
from pathlib import Path
import pytest
from server.dashboard import router, DIST_DIR


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_missing_asset_returns_404_not_html(client):
    """Missing CSS/JS/SVG assets must return 404, NEVER index.html with 200 OK."""
    # Under /assets/
    resp = client.get("/assets/nonexistent-style-12345.css")
    assert resp.status_code == 404
    assert "Asset not found" in resp.text
    assert "no-cache" in resp.headers.get("cache-control", "")

    # Under /dashboard/assets/
    resp = client.get("/dashboard/assets/missing-bundle-99999.js")
    assert resp.status_code == 404
    assert "Asset not found" in resp.text
    assert "no-cache" in resp.headers.get("cache-control", "")

    # With query params or hashes
    resp = client.get("/assets/missing-icon.svg?v=1.0")
    assert resp.status_code == 404
    assert "Asset not found" in resp.text


def test_existing_asset_returns_file_with_immutable_cache(client):
    """Real built assets must return 200 OK with long-lived immutable cache."""
    # Check if index.html exists in dist
    index_file = DIST_DIR / "index.html"
    if not index_file.is_file():
        pytest.skip("Frontend dist assets not built in this test run")

    # Find an asset in DIST_DIR / assets
    assets_dir = DIST_DIR / "assets"
    if assets_dir.is_dir():
        files = list(assets_dir.glob("*.js")) + list(assets_dir.glob("*.css"))
        if files:
            sample_asset = files[0].name
            # Test via /assets/{filename}
            resp = client.get(f"/assets/{sample_asset}")
            assert resp.status_code == 200
            assert "immutable" in resp.headers.get("cache-control", "").lower()

            # Test via /dashboard/assets/{filename}
            resp2 = client.get(f"/dashboard/assets/{sample_asset}")
            assert resp2.status_code == 200
            assert "immutable" in resp2.headers.get("cache-control", "").lower()


def test_spa_navigation_serves_index_html(client):
    """SPA document routes must return index.html with no-cache headers."""
    index_file = DIST_DIR / "index.html"
    if not index_file.is_file():
        pytest.skip("Frontend dist assets not built in this test run")

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "<!doctype html>" in resp.text.lower()
    assert "no-cache" in resp.headers.get("cache-control", "")

    resp_slash = client.get("/dashboard/")
    assert resp_slash.status_code == 200
    assert "<!doctype html>" in resp_slash.text.lower()

    resp_route = client.get("/dashboard/telemetry")
    assert resp_route.status_code == 200
    assert "<!doctype html>" in resp_route.text.lower()

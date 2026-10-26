def test_existing_home_route(client):
    """Verify original home route contract."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["application"] == "Cloud-Native Digital Resource Exchange Platform"
    assert data["status"] == "running"


def test_existing_db_test_route(client):
    """Verify original db-test route contract."""
    response = client.get("/db-test")
    assert response.status_code == 200
    data = response.get_json()
    assert data["database"] == "connected"
    assert data["result"] == 1


def test_existing_model_test_route(client):
    """Verify original model-test route contract."""
    response = client.get("/model-test")
    assert response.status_code == 200
    data = response.get_json()
    assert data["model"] == "User"
    assert data["status"] == "working"
    assert data["user_count"] >= 1


def test_frontend_ui_route(client):
    """Verify frontend UI is served."""
    response = client.get("/ui")
    assert response.status_code == 200
    assert b"CloudOps Sentinel" in response.data

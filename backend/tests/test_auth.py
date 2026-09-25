from datetime import timedelta
from app.core.security import create_access_token

TEST_DOC_ID = "22222222-2222-4222-8222-222222222222"


# -------------------------------------------------------------------
# Test Cases 1 - 4: Login Scenarios
# -------------------------------------------------------------------
def test_1_valid_login(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["employee_id"] == "POL-IO-001"
    assert data["user"]["role"] == "POLICE"
    assert "hashed_password" not in data["user"]


def test_2_wrong_password(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_3_unknown_employee_id(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "UNKNOWN_EMP", "password": "demo-password"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_4_inactive_user_login(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "INACTIVE001", "password": "demo-password"},
    )
    assert response.status_code == 401
    assert "inactive" in response.json()["detail"].lower()


# -------------------------------------------------------------------
# Test Cases 5 - 8: Token Validation & /auth/me
# -------------------------------------------------------------------
def test_5_missing_token(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code in (401, 403)


def test_6_invalid_token(client):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_token_string_here"},
    )
    assert response.status_code == 401


def test_7_expired_token(client):
    expired_jwt = create_access_token(
        subject="POL-IO-001",
        expires_delta=timedelta(seconds=-3600),
    )
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_jwt}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_8_auth_me_valid_token(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["employee_id"] == "POL-IO-001"
    assert user_data["role"] == "POLICE"
    assert "hashed_password" not in user_data


# -------------------------------------------------------------------
# Test Case 9: Protected Endpoint GET /api/v1/documents/{document_id}
# -------------------------------------------------------------------
def test_9_protected_document_endpoint(client):
    # Without token -> 401/403
    unauth_resp = client.get(f"/api/v1/documents/{TEST_DOC_ID}")
    assert unauth_resp.status_code in (401, 403)

    # With valid token -> 200
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    auth_resp = client.get(
        f"/api/v1/documents/{TEST_DOC_ID}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert auth_resp.status_code == 200
    doc_data = auth_resp.json()
    assert str(doc_data["id"]) == TEST_DOC_ID
    assert doc_data["title"] == "Test Evidence Doc"


# -------------------------------------------------------------------
# Test Cases 10 - 13: Role-Based Authorization
# -------------------------------------------------------------------
def test_10_officer_role_access(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/v1/auth/test-officer",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "Officer" in resp.json()["message"]


def test_11_reviewer_role_access(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "JUD-JDG-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/v1/auth/test-reviewer",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "Reviewer" in resp.json()["message"]


def test_12_admin_role_access(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "ADMIN001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/v1/auth/test-admin",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "Admin" in resp.json()["message"]


def test_13_unauthorized_role_access(client):
    # POL-IO-001 (OFFICER) trying to access ADMIN-only endpoint
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/v1/auth/test-admin",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "forbidden" in resp.json()["detail"].lower()


# -------------------------------------------------------------------
# Additional Auth Endpoints (Health Check & Logout)
# -------------------------------------------------------------------
def test_health_check_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_logout_endpoint(client):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"employee_id": "POL-IO-001", "password": "demo-password"},
    )
    token = login_resp.json()["access_token"]

    logout_resp = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 200
    assert "logged out" in logout_resp.json()["detail"].lower()

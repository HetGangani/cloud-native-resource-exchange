import io
import time
from unittest.mock import MagicMock, patch
import jwt
import pytest
from app.models import ActivityLog, Resource, User, db


def test_missing_jwt_on_protected_endpoints_returns_401(client):
    """Verify missing JWT returns 401 Unauthorized across all protected resource endpoints."""
    # 1. GET /resources
    res_list = client.get("/resources")
    assert res_list.status_code == 401
    assert "token" in res_list.get_json()["error"].lower()

    # 2. GET /resources/<id>
    res_get = client.get("/resources/1")
    assert res_get.status_code == 401
    assert "token" in res_get.get_json()["error"].lower()

    # 3. POST /resources
    res_post = client.post("/resources", data={"title": "Test"}, content_type="multipart/form-data")
    assert res_post.status_code == 401

    # 4. PUT /resources/<id>
    res_put = client.put("/resources/1", json={"title": "Updated"})
    assert res_put.status_code == 401

    # 5. PATCH /resources/<id>/approve
    res_approve = client.patch("/resources/1/approve")
    assert res_approve.status_code == 401

    # 6. PATCH /resources/<id>/reject
    res_reject = client.patch("/resources/1/reject")
    assert res_reject.status_code == 401

    # 7. DELETE /resources/<id>
    res_del = client.delete("/resources/1")
    assert res_del.status_code == 401


def test_invalid_and_expired_jwt_returns_401(client, app):
    """Verify invalid, malformed, or expired JWT returns 401 Unauthorized."""
    with app.app_context():
        # Malformed token
        bad_headers = {"Authorization": "Bearer not-a-valid-jwt-token"}
        res_bad = client.get("/resources", headers=bad_headers)
        assert res_bad.status_code == 401
        assert "invalid" in res_bad.get_json()["error"].lower()

        # Non-bearer header format
        basic_headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        res_basic = client.get("/resources", headers=basic_headers)
        assert res_basic.status_code == 401

        # Expired token
        expired_payload = {
            "sub": 1,
            "username": "testadmin",
            "is_admin": True,
            "exp": int(time.time()) - 3600  # 1 hour ago
        }
        expired_token = jwt.encode(expired_payload, app.config["SECRET_KEY"], algorithm="HS256")
        expired_headers = {"Authorization": f"Bearer {expired_token}"}
        res_exp = client.get("/resources", headers=expired_headers)
        assert res_exp.status_code == 401
        assert "expired" in res_exp.get_json()["error"].lower()


@patch("app.resources.delete_file_from_s3")
@patch("app.resources.upload_file_to_s3")
@patch("app.resources.generate_presigned_url")
def test_normal_user_permitted_operations(mock_presign, mock_upload, mock_delete_s3, client, app, regular_user_headers):
    """Verify normal authenticated user can upload, view approved resources, view own pending, update own, and delete own resource."""
    mock_upload.return_value = "resources/uuid_user_guide.pdf"
    mock_presign.return_value = "https://s3.amazonaws.com/test-bucket/user_guide.pdf?token=valid"
    mock_delete_s3.return_value = True

    with app.app_context():
        # 1. Normal user uploads resource -> starts pending (approved=False)
        upload_data = {
            "title": "Community Terraform Module",
            "description": "Reusable AWS ECS module",
            "file": (io.BytesIO(b"terraform code"), "main.tf"),
        }
        upload_res = client.post(
            "/resources",
            data=upload_data,
            headers=regular_user_headers,
            content_type="multipart/form-data"
        )
        assert upload_res.status_code == 201
        created = upload_res.get_json()
        assert created["approved"] is False
        assert created["title"] == "Community Terraform Module"
        resource_id = created["id"]

        # Verify publication audit log
        pub_log = ActivityLog.query.filter_by(action="resource_published").order_by(ActivityLog.id.desc()).first()
        assert pub_log is not None
        assert str(resource_id) in pub_log.detail

        # 2. Normal user views own pending resource directly -> 200 permitted
        own_res = client.get(f"/resources/{resource_id}", headers=regular_user_headers)
        assert own_res.status_code == 200
        assert own_res.get_json()["id"] == resource_id

        # 3. Normal user browses resources -> 200 permitted
        list_res = client.get("/resources", headers=regular_user_headers)
        assert list_res.status_code == 200

        # 4. Normal user updates their own resource metadata -> 200 permitted
        update_res = client.put(
            f"/resources/{resource_id}",
            json={"title": "Community Terraform Module v2", "description": "Updated ECS architecture"},
            headers=regular_user_headers
        )
        assert update_res.status_code == 200
        updated_data = update_res.get_json()
        assert updated_data["title"] == "Community Terraform Module v2"
        assert updated_data["description"] == "Updated ECS architecture"

        # Verify update audit log
        up_log = ActivityLog.query.filter_by(action="resource_updated").order_by(ActivityLog.id.desc()).first()
        assert up_log is not None
        assert str(resource_id) in up_log.detail

        # 5. Normal user deletes their own resource -> 200 permitted
        del_res = client.delete(f"/resources/{resource_id}", headers=regular_user_headers)
        assert del_res.status_code == 200
        assert del_res.get_json()["id"] == resource_id
        mock_delete_s3.assert_called_once_with("resources/uuid_user_guide.pdf")

        # Verify resource is removed from DB
        assert db.session.get(Resource, resource_id) is None

        # Verify deletion audit log
        del_log = ActivityLog.query.filter_by(action="resource_deleted").order_by(ActivityLog.id.desc()).first()
        assert del_log is not None
        assert str(resource_id) in del_log.detail


def test_normal_user_denied_admin_operations(client, app, regular_user_headers, auth_headers):
    """Verify normal authenticated user receives 403 Forbidden on administrative operations."""
    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()
        res = Resource(
            title="Admin Moderation Target",
            description="Target for permission tests",
            s3_key="resources/mod_target.pdf",
            uploaded_by=admin.id,
            approved=False
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # 1. Normal user attempts to approve -> 403
        approve_res = client.patch(f"/resources/{res_id}/approve", headers=regular_user_headers)
        assert approve_res.status_code == 403
        assert "administrator" in approve_res.get_json()["error"].lower()

        # 2. Normal user attempts to reject -> 403
        reject_res = client.patch(f"/resources/{res_id}/reject", headers=regular_user_headers)
        assert reject_res.status_code == 403
        assert "administrator" in reject_res.get_json()["error"].lower()

        # 3. Normal user cannot bypass approved filter with include_unapproved=true
        list_res = client.get("/resources?include_unapproved=true", headers=regular_user_headers)
        assert list_res.status_code == 200
        ids = [r["id"] for r in list_res.get_json()]
        assert res_id not in ids

        # Verify access_denied audit logs recorded
        denied_log = ActivityLog.query.filter_by(action="access_denied").order_by(ActivityLog.id.desc()).first()
        assert denied_log is not None


@patch("app.resources.delete_file_from_s3")
def test_administrator_permitted_operations(mock_delete_s3, client, app, auth_headers):
    """Verify administrator can approve, reject, update metadata, and delete any resource."""
    mock_delete_s3.return_value = True

    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()
        res = Resource(
            title="Security Audit Checklist",
            description="Cloud security compliance guide",
            s3_key="resources/audit.pdf",
            uploaded_by=admin.id,
            approved=False
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # 1. Admin views unapproved resources with flag
        admin_list = client.get("/resources?include_unapproved=true", headers=auth_headers)
        assert admin_list.status_code == 200
        ids = [r["id"] for r in admin_list.get_json()]
        assert res_id in ids

        # 2. Admin approves resource
        approve_res = client.patch(f"/resources/{res_id}/approve", headers=auth_headers)
        assert approve_res.status_code == 200
        assert approve_res.get_json()["approved"] is True

        # 3. Admin updates resource metadata
        update_res = client.put(
            f"/resources/{res_id}",
            json={"title": "Security Audit Checklist (v2026)", "description": "Updated guidelines"},
            headers=auth_headers
        )
        assert update_res.status_code == 200
        assert update_res.get_json()["title"] == "Security Audit Checklist (v2026)"

        # 4. Admin rejects resource
        reject_res = client.patch(f"/resources/{res_id}/reject", headers=auth_headers)
        assert reject_res.status_code == 200
        assert reject_res.get_json()["resource"]["approved"] is False

        # 5. Admin deletes resource
        del_res = client.delete(f"/resources/{res_id}", headers=auth_headers)
        assert del_res.status_code == 200
        mock_delete_s3.assert_called_once_with("resources/audit.pdf")


def test_access_to_pending_resources_by_normal_users(client, app, auth_headers):
    """Verify pending resources remain hidden from other normal users, returning 403 on direct access."""
    with app.app_context():
        # Register User Alice
        client.post("/auth/register", json={
            "username": "user_alice",
            "email": "alice@sentinel.io",
            "password": "Password123"
        })
        alice_login = client.post("/auth/login", json={"username": "user_alice", "password": "Password123"})
        alice_token = alice_login.get_json()["token"]
        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        alice_user = User.query.filter_by(username="user_alice").first()

        # Register User Bob
        client.post("/auth/register", json={
            "username": "user_bob",
            "email": "bob@sentinel.io",
            "password": "Password123"
        })
        bob_login = client.post("/auth/login", json={"username": "user_bob", "password": "Password123"})
        bob_token = bob_login.get_json()["token"]
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # Alice creates a pending resource
        res = Resource(
            title="Alice Private Draft",
            description="Alice draft awaiting approval",
            s3_key="resources/alice_draft.pdf",
            uploaded_by=alice_user.id,
            approved=False
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # Bob browses resources -> Alice's pending resource is NOT in list
        bob_list = client.get("/resources", headers=bob_headers)
        assert bob_list.status_code == 200
        assert res_id not in [r["id"] for r in bob_list.get_json()]

        # Bob attempts direct access to Alice's pending resource -> 403 Forbidden
        bob_get = client.get(f"/resources/{res_id}", headers=bob_headers)
        assert bob_get.status_code == 403
        assert "pending approval" in bob_get.get_json()["error"].lower()

        # Verify access_denied log recorded for Bob's attempt
        access_log = ActivityLog.query.filter_by(
            action="access_denied",
            user_id=bob_login.get_json()["user"]["id"]
        ).order_by(ActivityLog.id.desc()).first()
        assert access_log is not None

        # Alice accesses her OWN pending resource -> 200 OK
        alice_get = client.get(f"/resources/{res_id}", headers=alice_headers)
        assert alice_get.status_code == 200
        assert alice_get.get_json()["title"] == "Alice Private Draft"

        # Admin accesses pending resource -> 200 OK
        admin_get = client.get(f"/resources/{res_id}", headers=auth_headers)
        assert admin_get.status_code == 200


@patch("app.resources.delete_file_from_s3")
def test_resource_ownership_modification_and_deletion(mock_delete_s3, client, app, auth_headers):
    """Verify non-owners receive 403 when attempting to update or delete another user's resource."""
    mock_delete_s3.return_value = True

    with app.app_context():
        # Create Owner User
        client.post("/auth/register", json={
            "username": "resource_owner_user",
            "email": "owner@sentinel.io",
            "password": "Password123"
        })
        owner_login = client.post("/auth/login", json={"username": "resource_owner_user", "password": "Password123"})
        owner_headers = {"Authorization": f"Bearer {owner_login.get_json()['token']}"}
        owner_user = User.query.filter_by(username="resource_owner_user").first()

        # Create Attacker User
        client.post("/auth/register", json={
            "username": "other_normal_user",
            "email": "other@sentinel.io",
            "password": "Password123"
        })
        other_login = client.post("/auth/login", json={"username": "other_normal_user", "password": "Password123"})
        other_headers = {"Authorization": f"Bearer {other_login.get_json()['token']}"}

        # Owner has a resource
        res = Resource(
            title="Owner Exclusive Blueprint",
            description="Created by owner",
            s3_key="resources/owner_blueprint.pdf",
            uploaded_by=owner_user.id,
            approved=True
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # 1. Attacker tries to update metadata -> 403 Forbidden
        attack_update = client.put(
            f"/resources/{res_id}",
            json={"title": "Hacked Title"},
            headers=other_headers
        )
        assert attack_update.status_code == 403
        assert "permission denied" in attack_update.get_json()["error"].lower()

        # 2. Attacker tries to delete -> 403 Forbidden
        attack_del = client.delete(f"/resources/{res_id}", headers=other_headers)
        assert attack_del.status_code == 403
        assert "permission denied" in attack_del.get_json()["error"].lower()

        # 3. Owner updates own metadata -> 200
        owner_update = client.put(
            f"/resources/{res_id}",
            json={"title": "Owner Refined Blueprint"},
            headers=owner_headers
        )
        assert owner_update.status_code == 200
        assert owner_update.get_json()["title"] == "Owner Refined Blueprint"

        # 4. Owner deletes own resource -> 200
        owner_del = client.delete(f"/resources/{res_id}", headers=owner_headers)
        assert owner_del.status_code == 200
        mock_delete_s3.assert_called_once_with("resources/owner_blueprint.pdf")


def test_invalid_approval_transitions(client, app, auth_headers):
    """Verify state transitions and invalid/repeated transitions return 400 Bad Request."""
    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()

        # Create a pending resource (status='pending', approved=False)
        res = Resource(
            title="Transition Test Resource",
            description="Testing state transition logic",
            s3_key="resources/trans.pdf",
            uploaded_by=admin.id,
            status="pending",
            approved=False
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # 1. Rejecting a pending resource -> 200 OK (valid explicit moderation)
        reject_res = client.patch(f"/resources/{res_id}/reject", headers=auth_headers)
        assert reject_res.status_code == 200
        assert reject_res.get_json()["resource"]["status"] == "rejected"
        assert reject_res.get_json()["resource"]["approved"] is False

        # 2. Rejecting an already rejected resource -> 400 Bad Request
        bad_reject = client.patch(f"/resources/{res_id}/reject", headers=auth_headers)
        assert bad_reject.status_code == 400
        assert "already rejected" in bad_reject.get_json()["error"].lower()

        # 3. Accidental/direct approval of rejected resource without reactivate flag -> 400 Bad Request
        bad_approve_rejected = client.patch(f"/resources/{res_id}/approve", headers=auth_headers)
        assert bad_approve_rejected.status_code == 400
        assert "reactivation" in bad_approve_rejected.get_json()["error"].lower()

        # 4. Deliberate reactivation approval (rejected -> approved) -> 200 OK
        reactivate_res = client.patch(f"/resources/{res_id}/approve", json={"reactivate": True}, headers=auth_headers)
        assert reactivate_res.status_code == 200
        assert reactivate_res.get_json()["status"] == "approved"
        assert reactivate_res.get_json()["approved"] is True

        # 5. Approving an already approved resource -> 400 Bad Request
        bad_approve = client.patch(f"/resources/{res_id}/approve", headers=auth_headers)
        assert bad_approve.status_code == 400
        assert "already approved" in bad_approve.get_json()["error"].lower()

        # 6. Revoking approval (approved -> rejected) -> 200 OK
        revoke_res = client.patch(f"/resources/{res_id}/reject", headers=auth_headers)
        assert revoke_res.status_code == 200
        assert revoke_res.get_json()["resource"]["status"] == "rejected"
        assert revoke_res.get_json()["resource"]["approved"] is False



@patch("app.resources.delete_file_from_s3")
def test_storage_failure_during_deletion_aborts_db_deletion(mock_delete_s3, client, app, regular_user_headers):
    """Verify if S3 deletion fails, database deletion is rolled back and no success log is written."""
    mock_delete_s3.side_effect = RuntimeError("S3 Connection Refused / Storage Unreachable")

    with app.app_context():
        user = User.query.filter_by(username="fixture_reg_user").first()
        res = Resource(
            title="Critical Storage Guard Resource",
            description="Resource with failing storage cleanup",
            s3_key="resources/critical_fail.pdf",
            uploaded_by=user.id,
            approved=True
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # Attempt deletion
        del_res = client.delete(f"/resources/{res_id}", headers=regular_user_headers)
        assert del_res.status_code == 500
        assert "deletion aborted" in del_res.get_json()["error"].lower()

        # Verify DB record is STILL present (rollback succeeded)
        still_exists = db.session.get(Resource, res_id)
        assert still_exists is not None
        assert still_exists.title == "Critical Storage Guard Resource"

        # Verify NO resource_deleted success log was recorded
        misleading_log = ActivityLog.query.filter_by(
            action="resource_deleted",
            detail=f"Resource 'Critical Storage Guard Resource' (ID {res_id}) deleted by 'fixture_reg_user'"
        ).first()
        assert misleading_log is None

        # Clean up test-created resource to prevent database pollution
        db.session.delete(still_exists)
        db.session.commit()


def test_resource_metadata_update_validation(client, app, regular_user_headers):
    """Verify input validation rules for metadata updates."""
    with app.app_context():
        user = User.query.filter_by(username="fixture_reg_user").first()
        res = Resource(
            title="Validation Test Target",
            description="Original description",
            s3_key="resources/val.pdf",
            uploaded_by=user.id,
            approved=True
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # Non-JSON body
        res_text = client.put(f"/resources/{res_id}", data="not json", content_type="text/plain", headers=regular_user_headers)
        assert res_text.status_code == 400

        # Empty title
        res_empty = client.put(f"/resources/{res_id}", json={"title": "   "}, headers=regular_user_headers)
        assert res_empty.status_code == 400
        assert "title cannot be empty" in res_empty.get_json()["error"].lower()

        # Exceeding title length
        res_long = client.put(f"/resources/{res_id}", json={"title": "A" * 201}, headers=regular_user_headers)
        assert res_long.status_code == 400
        assert "exceed 200" in res_long.get_json()["error"].lower()

        # No fields provided
        res_none = client.put(f"/resources/{res_id}", json={}, headers=regular_user_headers)
        assert res_none.status_code == 400

        # Resource still unchanged
        db_res = db.session.get(Resource, res_id)
        assert db_res.title == "Validation Test Target"

        # Clean up test-created resource to prevent database pollution
        db.session.delete(db_res)
        db.session.commit()


def test_frontend_ui_route_and_logout_flow(client, app, regular_user_headers):
    """Verify frontend UI is accessible and logout disables client session."""
    # 1. Public UI route is accessible without credentials
    ui_res = client.get("/ui")
    assert ui_res.status_code == 200
    html_text = ui_res.get_data(as_text=True)
    assert "CloudOps Sentinel" in html_text
    assert "authView" in html_text
    assert "dashboardView" in html_text

    # 2. Authenticated user calls /auth/logout
    logout_res = client.post("/auth/logout", headers=regular_user_headers)
    assert logout_res.status_code == 200
    assert "logged out" in logout_res.get_json()["message"].lower()

    # 3. Subsequent unauthenticated request to protected endpoint is denied
    res_after = client.get("/resources")
    assert res_after.status_code == 401


@patch("app.resources.upload_file_to_s3")
@patch("app.resources.generate_presigned_url")
def test_resource_lifecycle(mock_presign, mock_upload, client, auth_headers, app):
    """Preserve existing full resource lifecycle: upload -> browse -> search -> approve."""
    mock_upload.return_value = "resources/test-uuid_document.pdf"
    mock_presign.return_value = "https://s3.amazonaws.com/test-bucket/document.pdf?token=xyz"

    with app.app_context():
        # 1. Upload resource
        data = {
            "title": "Kubernetes Architecture Guide",
            "description": "Comprehensive guide for cloud deployments",
            "file": (io.BytesIO(b"%PDF-1.4 test binary"), "document.pdf"),
        }
        upload_res = client.post(
            "/resources",
            data=data,
            headers=auth_headers,
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        created = upload_res.get_json()
        assert created["title"] == "Kubernetes Architecture Guide"
        assert created["approved"] is False
        assert created["s3_key"] == "resources/test-uuid_document.pdf"
        resource_id = created["id"]

        # Verify ActivityLog entry for publish
        pub_log = ActivityLog.query.filter_by(
            action="resource_published"
        ).order_by(ActivityLog.id.desc()).first()
        assert pub_log is not None
        assert str(resource_id) in pub_log.detail

        # 2. Browse before approval -> Should not appear in default list
        browse_res = client.get("/resources", headers=auth_headers)
        assert browse_res.status_code == 200
        approved_ids = [r["id"] for r in browse_res.get_json()]
        assert resource_id not in approved_ids

        # 3. Approve resource as admin
        approve_res = client.patch(
            f"/resources/{resource_id}/approve",
            headers=auth_headers,
        )
        assert approve_res.status_code == 200
        approved_data = approve_res.get_json()
        assert approved_data["approved"] is True

        # Verify ActivityLog entry for approval
        app_log = ActivityLog.query.filter_by(
            action="resource_approved"
        ).order_by(ActivityLog.id.desc()).first()
        assert app_log is not None
        assert str(resource_id) in app_log.detail

        # 4. Browse after approval -> Should appear in default list
        browse_after = client.get("/resources", headers=auth_headers)
        assert browse_after.status_code == 200
        ids_after = [r["id"] for r in browse_after.get_json()]
        assert resource_id in ids_after

        # 5. Search with matching query
        search_res = client.get("/resources?query=Kubernetes", headers=auth_headers)
        assert search_res.status_code == 200
        results = search_res.get_json()
        assert len(results) >= 1
        assert any(r["id"] == resource_id for r in results)

        # 6. Search with non-matching query
        no_match_res = client.get("/resources?query=NonExistentKeywordXYZ", headers=auth_headers)
        assert no_match_res.status_code == 200
        assert len(no_match_res.get_json()) == 0


# ============================================================================
# Phase 4: Explicit Lifecycle, Pagination, Filtering, and Security Tests
# ============================================================================

@patch("app.resources.upload_file_to_s3")
def test_phase4_new_upload_starts_in_pending_status(mock_upload, client, app, regular_user_headers):
    """Verify newly uploaded resources receive explicit status='pending' and approved=False."""
    mock_upload.return_value = "resources/phase4_upload.pdf"
    upload_data = {
        "title": "Phase 4 Lifecycle Upload",
        "description": "Initial pending status verification",
        "file": (io.BytesIO(b"content"), "upload.pdf"),
    }
    res = client.post("/resources", data=upload_data, headers=regular_user_headers, content_type="multipart/form-data")
    assert res.status_code == 201
    data = res.get_json()
    assert data["status"] == "pending"
    assert data["approved"] is False

    with app.app_context():
        db_res = db.session.get(Resource, data["id"])
        assert db_res.status == "pending"
        assert db_res.approved is False


def test_phase4_invalid_lifecycle_state_rejected_by_db_constraint(app):
    """Verify invalid lifecycle state is rejected at application level and database constraint."""
    with app.app_context():
        user = User.query.first()
        # 1. Application-level validator rejects invalid state
        with pytest.raises(ValueError):
            Resource(
                title="Invalid Lifecycle Resource",
                description="Testing invalid status constraint",
                s3_key="resources/invalid_state.pdf",
                uploaded_by=user.id,
                status="invalid_state",
            )

        # 2. Database check constraint rejects invalid state in SQL
        with pytest.raises(Exception):
            db.session.execute(
                db.text("INSERT INTO resources (title, s3_key, uploaded_by, status, approved) VALUES ('raw', 'raw.pdf', :uid, 'bad_status', false)"),
                {"uid": user.id}
            )
            db.session.commit()
        db.session.rollback()


def test_phase4_non_admin_cannot_approve_or_reject(client, app, regular_user_headers):
    """Verify non-admin users cannot approve or reject resources (HTTP 403 Forbidden)."""
    with app.app_context():
        user = User.query.filter_by(username="fixture_reg_user").first()
        res = Resource(
            title="Non-Admin Moderation Guard",
            description="Testing admin RBAC",
            s3_key="resources/guard.pdf",
            uploaded_by=user.id,
            status="pending",
            approved=False,
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # Regular user attempt approve -> 403
        app_res = client.patch(f"/resources/{res_id}/approve", headers=regular_user_headers)
        assert app_res.status_code == 403

        # Regular user attempt reject -> 403
        rej_res = client.patch(f"/resources/{res_id}/reject", headers=regular_user_headers)
        assert rej_res.status_code == 403


@patch("app.resources.generate_presigned_url")
def test_phase4_ordinary_user_cannot_see_or_download_unapproved_or_rejected(mock_presign, client, app, auth_headers):
    """Verify ordinary users cannot view, list, or download other users' pending or rejected resources."""
    mock_presign.return_value = "https://s3.example.com/download"
    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()

        # Register two normal users: userA (owner) and userB (stranger)
    reg_a = client.post("/auth/register", json={
        "username": "user_owner_p4",
        "email": "owner_p4@sentinel.local",
        "password": "OwnerPassword123"
    })
    assert reg_a.status_code == 201

    reg_b = client.post("/auth/register", json={
        "username": "user_stranger_p4",
        "email": "stranger_p4@sentinel.local",
        "password": "StrangerPassword123"
    })
    assert reg_b.status_code == 201

    with app.app_context():
        user_a = User.query.filter_by(username="user_owner_p4").first()
        user_b = User.query.filter_by(username="user_stranger_p4").first()

        # Create pending, rejected, and approved resources owned by user_a
        pending_res = Resource(
            title="User A Pending Resource",
            description="Pending moderation",
            s3_key="resources/user_a_pending.pdf",
            uploaded_by=user_a.id,
            status="pending",
            approved=False,
        )
        rejected_res = Resource(
            title="User A Rejected Resource",
            description="Explicitly rejected",
            s3_key="resources/user_a_rejected.pdf",
            uploaded_by=user_a.id,
            status="rejected",
            approved=False,
        )
        approved_res = Resource(
            title="User A Approved Resource",
            description="Approved for everyone",
            s3_key="resources/user_a_approved.pdf",
            uploaded_by=user_a.id,
            status="approved",
            approved=True,
        )
        db.session.add_all([pending_res, rejected_res, approved_res])
        db.session.commit()

        pending_id = pending_res.id
        rejected_id = rejected_res.id
        approved_id = approved_res.id

    # Login as user_b (stranger)
    login_b = client.post("/auth/login", json={"username": "user_stranger_p4", "password": "StrangerPassword123"})
    assert login_b.status_code == 200
    token_b = login_b.get_json()["token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 1. Stranger GET /resources/<pending_id> -> 403 Forbidden
    get_p = client.get(f"/resources/{pending_id}", headers=headers_b)
    assert get_p.status_code == 403
    assert "pending approval" in get_p.get_json()["error"].lower()

    # 2. Stranger GET /resources/<rejected_id> -> 403 Forbidden
    get_r = client.get(f"/resources/{rejected_id}", headers=headers_b)
    assert get_r.status_code == 403
    assert "rejected" in get_r.get_json()["error"].lower()

    # 3. Stranger GET /resources -> only approved_id visible
    list_b = client.get("/resources", headers=headers_b)
    assert list_b.status_code == 200
    ids_b = [r["id"] for r in list_b.get_json()]
    assert approved_id in ids_b
    assert pending_id not in ids_b
    assert rejected_id not in ids_b

    # 4. Stranger cannot bypass via ?status=pending or ?status=rejected
    list_p_filter = client.get("/resources?status=pending", headers=headers_b)
    assert list_p_filter.status_code == 200
    assert pending_id not in [r["id"] for r in list_p_filter.get_json()]

    # Login as user_a (owner)
    login_a = client.post("/auth/login", json={"username": "user_owner_p4", "password": "OwnerPassword123"})
    assert login_a.status_code == 200
    token_a = login_a.get_json()["token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Owner CAN view their own pending and rejected resources
    get_own_p = client.get(f"/resources/{pending_id}", headers=headers_a)
    assert get_own_p.status_code == 200
    assert get_own_p.get_json()["status"] == "pending"

    get_own_r = client.get(f"/resources/{rejected_id}", headers=headers_a)
    assert get_own_r.status_code == 200
    assert get_own_r.get_json()["status"] == "rejected"

    # Admin CAN view pending and rejected resources
    get_admin_p = client.get(f"/resources/{pending_id}", headers=auth_headers)
    assert get_admin_p.status_code == 200
    assert get_admin_p.get_json()["status"] == "pending"


def test_phase4_bounded_pagination_and_validation(client, app, auth_headers):
    """Verify bounded pagination parameters, ordering, metadata, and invalid value validation."""
    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()
        # Seed 5 distinct test resources
        for i in range(1, 6):
            r = Resource(
                title=f"Pagination Item {i:02d}",
                description=f"Pagination test description {i}",
                s3_key=f"resources/page_{i}.pdf",
                uploaded_by=admin.id,
                status="approved",
                approved=True,
            )
            db.session.add(r)
        db.session.commit()

    # 1. Valid paginated request page 1, per_page 2
    res = client.get("/resources?page=1&per_page=2", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, dict)
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "per_page" in data
    assert "total_pages" in data
    assert data["page"] == 1
    assert data["per_page"] == 2
    assert len(data["items"]) == 2
    assert data["has_next"] is True
    assert data["has_prev"] is False

    # Check RFC pagination headers
    assert "X-Total-Count" in res.headers
    assert res.headers["X-Page"] == "1"
    assert res.headers["X-Per-Page"] == "2"

    # Stable ordering: newest first (created_at DESC, id DESC)
    items = data["items"]
    assert items[0]["id"] > items[1]["id"]

    # 2. Page 2
    res_p2 = client.get("/resources?page=2&per_page=2", headers=auth_headers)
    assert res_p2.status_code == 200
    data_p2 = res_p2.get_json()
    assert data_p2["page"] == 2
    assert data_p2["has_prev"] is True
    # Ensure distinct items between page 1 and page 2
    p1_ids = {r["id"] for r in data["items"]}
    p2_ids = {r["id"] for r in data_p2["items"]}
    assert p1_ids.isdisjoint(p2_ids)

    # 3. Invalid page values -> 400
    assert client.get("/resources?page=0", headers=auth_headers).status_code == 400
    assert client.get("/resources?page=-1", headers=auth_headers).status_code == 400
    assert client.get("/resources?page=invalid", headers=auth_headers).status_code == 400

    # 4. Invalid per_page values -> 400
    assert client.get("/resources?per_page=0", headers=auth_headers).status_code == 400
    assert client.get("/resources?per_page=-5", headers=auth_headers).status_code == 400
    assert client.get("/resources?per_page=abc", headers=auth_headers).status_code == 400

    # 5. per_page capped at 100
    res_cap = client.get("/resources?page=1&per_page=500", headers=auth_headers)
    assert res_cap.status_code == 200
    assert res_cap.get_json()["per_page"] == 100


def test_phase4_status_filtering_and_security(client, app, auth_headers, regular_user_headers):
    """Verify status filter options and prevent authorization bypass."""
    # 1. Invalid status filter -> 400
    bad_status = client.get("/resources?status=unknown_status", headers=auth_headers)
    assert bad_status.status_code == 400
    assert "invalid status filter" in bad_status.get_json()["error"].lower()

    # 2. Admin filter by status=pending
    pending_res = client.get("/resources?status=pending", headers=auth_headers)
    assert pending_res.status_code == 200
    pending_items = pending_res.get_json()
    assert all(r["status"] == "pending" for r in pending_items)

    # 3. Admin filter by status=approved
    approved_res = client.get("/resources?status=approved", headers=auth_headers)
    assert approved_res.status_code == 200
    approved_items = approved_res.get_json()
    assert all(r["status"] == "approved" for r in approved_items)

    # 4. Admin filter by status=rejected
    rejected_res = client.get("/resources?status=rejected", headers=auth_headers)
    assert rejected_res.status_code == 200
    rejected_items = rejected_res.get_json()
    assert all(r["status"] == "rejected" for r in rejected_items)


def test_phase4_audit_logging_for_lifecycle_transitions(client, app, auth_headers):
    """Verify audit log entries record actor, resource, and action for approve, reject, and reactivation."""
    with app.app_context():
        admin = User.query.filter_by(username="testadmin").first()
        res = Resource(
            title="Audit Verification Lifecycle Target",
            description="Audit logging verification",
            s3_key="resources/audit_target.pdf",
            uploaded_by=admin.id,
            status="pending",
            approved=False,
        )
        db.session.add(res)
        db.session.commit()
        res_id = res.id

        # 1. Admin rejects pending resource
        client.patch(f"/resources/{res_id}/reject", headers=auth_headers)
        rej_log = ActivityLog.query.filter_by(action="resource_rejected").order_by(ActivityLog.id.desc()).first()
        assert rej_log is not None
        assert rej_log.user_id == admin.id
        assert str(res_id) in rej_log.detail

        # 2. Admin reactivates rejected resource
        client.patch(f"/resources/{res_id}/approve", json={"reactivate": True}, headers=auth_headers)
        app_log = ActivityLog.query.filter_by(action="resource_approved").order_by(ActivityLog.id.desc()).first()
        assert app_log is not None
        assert app_log.user_id == admin.id
        assert str(res_id) in app_log.detail


@patch("app.resources.generate_presigned_url")
def test_phase4_authoritative_status_blocks_unauthorized_download_even_if_approved_is_true(mock_presign, client, app, auth_headers):
    """Regression test: verify status='pending' is authoritative even if approved=True in database."""
    import uuid
    mock_presign.return_value = "https://s3.example.com/unauthorized_leak.pdf"
    u_suffix = uuid.uuid4().hex[:6]
    with app.app_context():
        # Create an owner and a stranger
        owner = User(username=f"regr_o1_{u_suffix}", email=f"regr_o1_{u_suffix}@sentinel.local", is_admin=False)
        owner.password_hash = "hash123"
        stranger = User(username=f"regr_s1_{u_suffix}", email=f"regr_s1_{u_suffix}@sentinel.local", is_admin=False)
        stranger.password_hash = "hash123"
        db.session.add_all([owner, stranger])
        db.session.commit()

        owner_id = owner.id
        stranger_id = stranger.id
        from app.auth import generate_jwt_token
        stranger_token = generate_jwt_token(stranger)
        owner_token = generate_jwt_token(owner)

        # Insert resource with conflicting status='pending' and approved=True directly
        res = Resource(
            title=f"Conflicting Pending Resource {u_suffix}",
            description="Testing authoritative status logic",
            s3_key="resources/conflict_pending.pdf",
            uploaded_by=owner_id,
            status="pending",
            approved=False,
        )
        db.session.add(res)
        db.session.commit()
        # Force raw database discrepancy to test bug condition
        db.session.execute(
            db.text("UPDATE resources SET approved = true WHERE id = :id"),
            {"id": res.id}
        )
        db.session.commit()
        res_id = res.id

        # Verify DB actually has the discrepancy
        raw_row = db.session.execute(
            db.text("SELECT status, approved FROM resources WHERE id = :id"),
            {"id": res_id}
        ).fetchone()
        assert raw_row[0] == "pending"
        assert raw_row[1] is True

    stranger_headers = {"Authorization": f"Bearer {stranger_token}"}
    owner_headers = {"Authorization": f"Bearer {owner_token}"}

    try:
        # 1. Stranger calls GET /resources/<res_id> -> MUST return 403 Forbidden
        res_get = client.get(f"/resources/{res_id}", headers=stranger_headers)
        assert res_get.status_code == 403
        assert "pending approval" in res_get.get_json()["error"].lower()

        # 2. Stranger calls GET /resources -> MUST NOT list the resource
        res_list = client.get("/resources", headers=stranger_headers)
        assert res_list.status_code == 200
        assert res_id not in [r["id"] for r in res_list.get_json()]

        # 3. Owner CAN view their own pending resource
        owner_get = client.get(f"/resources/{res_id}", headers=owner_headers)
        assert owner_get.status_code == 200
        assert owner_get.get_json()["status"] == "pending"
        assert owner_get.get_json()["approved"] is False

        # 4. Admin CAN view the resource
        admin_get = client.get(f"/resources/{res_id}", headers=auth_headers)
        assert admin_get.status_code == 200
    finally:
        with app.app_context():
            clean_res = db.session.get(Resource, res_id)
            if clean_res:
                db.session.delete(clean_res)
            db.session.commit()
            u1 = db.session.get(User, owner_id)
            if u1:
                db.session.delete(u1)
            u2 = db.session.get(User, stranger_id)
            if u2:
                db.session.delete(u2)
            db.session.commit()


@patch("app.resources.generate_presigned_url")
def test_phase4_authoritative_status_blocks_rejected_download_even_if_approved_is_true(mock_presign, client, app, auth_headers):
    """Regression test: verify status='rejected' is authoritative even if approved=True in database."""
    import uuid
    mock_presign.return_value = "https://s3.example.com/unauthorized_leak.pdf"
    u_suffix = uuid.uuid4().hex[:6]
    with app.app_context():
        owner = User(username=f"regr_o2_{u_suffix}", email=f"regr_o2_{u_suffix}@sentinel.local", is_admin=False)
        owner.password_hash = "hash123"
        stranger = User(username=f"regr_s2_{u_suffix}", email=f"regr_s2_{u_suffix}@sentinel.local", is_admin=False)
        stranger.password_hash = "hash123"
        db.session.add_all([owner, stranger])
        db.session.commit()

        owner_id = owner.id
        stranger_id = stranger.id
        from app.auth import generate_jwt_token
        stranger_token = generate_jwt_token(stranger)
        owner_token = generate_jwt_token(owner)

        # Insert resource with conflicting status='rejected' and approved=True directly
        res = Resource(
            title=f"Conflicting Rejected Resource {u_suffix}",
            description="Testing authoritative rejected status logic",
            s3_key="resources/conflict_rejected.pdf",
            uploaded_by=owner_id,
            status="rejected",
            approved=False,
        )
        db.session.add(res)
        db.session.commit()
        db.session.execute(
            db.text("UPDATE resources SET approved = true WHERE id = :id"),
            {"id": res.id}
        )
        db.session.commit()
        res_id = res.id

    stranger_headers = {"Authorization": f"Bearer {stranger_token}"}
    owner_headers = {"Authorization": f"Bearer {owner_token}"}

    try:
        # 1. Stranger calls GET /resources/<res_id> -> MUST return 403 Forbidden
        res_get = client.get(f"/resources/{res_id}", headers=stranger_headers)
        assert res_get.status_code == 403
        assert "rejected" in res_get.get_json()["error"].lower()

        # 2. Owner CAN view their own rejected resource
        owner_get = client.get(f"/resources/{res_id}", headers=owner_headers)
        assert owner_get.status_code == 200
        assert owner_get.get_json()["status"] == "rejected"
        assert owner_get.get_json()["approved"] is False
    finally:
        with app.app_context():
            clean_res = db.session.get(Resource, res_id)
            if clean_res:
                db.session.delete(clean_res)
            db.session.commit()
            u1 = db.session.get(User, owner_id)
            if u1:
                db.session.delete(u1)
            u2 = db.session.get(User, stranger_id)
            if u2:
                db.session.delete(u2)
            db.session.commit()


def test_phase4_model_bidirectional_synchronization(app):
    """Verify Resource model synchronizes status and approved bi-directionally."""
    with app.app_context():
        user = User.query.first()

        # 1. approved=True sets status='approved'
        r1 = Resource(title="Sync 1", s3_key="key1.pdf", uploaded_by=user.id, approved=True)
        assert r1.status == "approved"
        assert r1.approved is True

        # 2. approved=False sets status='pending'
        r2 = Resource(title="Sync 2", s3_key="key2.pdf", uploaded_by=user.id, approved=False)
        assert r2.status == "pending"
        assert r2.approved is False

        # 3. status='approved' sets approved=True
        r3 = Resource(title="Sync 3", s3_key="key3.pdf", uploaded_by=user.id, status="approved")
        assert r3.status == "approved"
        assert r3.approved is True

        # 4. status='rejected' sets approved=False
        r4 = Resource(title="Sync 4", s3_key="key4.pdf", uploaded_by=user.id, status="rejected")
        assert r4.status == "rejected"
        assert r4.approved is False

        # 5. Dynamic attribute assignment
        r5 = Resource(title="Sync 5", s3_key="key5.pdf", uploaded_by=user.id)
        assert r5.status == "pending"
        assert r5.approved is False

        r5.status = "approved"
        assert r5.approved is True

        r5.status = "rejected"
        assert r5.approved is False

        r5.approved = True
        assert r5.status == "approved"

        r5.approved = False
        assert r5.status == "pending"

        # 6. Invalid status raises ValueError
        with pytest.raises(ValueError):
            r5.status = "invalid_status_xyz"



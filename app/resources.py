import logging
import math
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import or_

from app.auth import admin_required, token_required
from app.models import ActivityLog, Resource, User, db
from app.storage import delete_file_from_s3, generate_presigned_url, upload_file_to_s3

resources_bp = Blueprint("resources", __name__, url_prefix="/resources")
logger = logging.getLogger(__name__)

VALID_STATUSES = {"pending", "approved", "rejected"}


def record_activity_log(user_id, action, detail):
    """Safely record an audit log entry in the database.
    
    Ensures audit logs do not leak credentials, passwords, or tokens.
    """
    try:
        activity = ActivityLog(
            user_id=user_id,
            action=action,
            detail=detail,
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to record ActivityLog for action='{action}': {e}")


def serialize_resource(resource, current_user=None):
    """Serialize Resource model to JSON dictionary.
    
    Security rules:
      - presigned download URL is ONLY generated if the resource is
        approved OR if the requester is an administrator or the original uploader.
      - s3_key is exposed only to authorized users.
      - Provides both explicit 'status' and backward-compatible 'approved' boolean.
    """
    uploader_name = resource.uploader.username if resource.uploader else "unknown"
    download_url = None

    status_val = getattr(resource, "status", None) or ("approved" if resource.approved else "pending")
    is_approved = (status_val == "approved")

    is_authorized = is_approved or (
        current_user is not None and (
            getattr(current_user, "is_admin", False) or current_user.id == resource.uploaded_by
        )
    )

    if is_authorized:
        try:
            download_url = generate_presigned_url(resource.s3_key)
        except Exception as e:
            logger.warning(f"Could not generate presigned URL for {resource.s3_key}: {e}")

    return {
        "id": resource.id,
        "title": resource.title,
        "description": resource.description,
        "s3_key": resource.s3_key if is_authorized else None,
        "uploaded_by": resource.uploaded_by,
        "uploader_username": uploader_name,
        "status": status_val,
        "approved": is_approved,
        "created_at": resource.created_at.isoformat() if resource.created_at else None,
        "download_url": download_url,
    }


@resources_bp.route("", methods=["GET"])
@token_required
def list_resources():
    """Browse and search resources with bounded pagination and filtering.
    
    Protected route: requires valid authentication token for all users.
    Query parameters:
      query: simple SQL LIKE match on title or description
      status: optional filter ('pending', 'approved', 'rejected')
      page: 1-indexed page number (default: 1)
      per_page: items per page (default: 20, max: 100)
      limit: legacy limit (default: 50, max: 100)
      include_unapproved: 'true' (legacy flag, strictly gated to admin token)
    """
    current_user = g.current_user
    is_admin = getattr(current_user, "is_admin", False)

    # 1. Parse and validate pagination parameters
    has_page_param = "page" in request.args
    has_per_page_param = "per_page" in request.args
    is_paginated_request = has_page_param or has_per_page_param

    page_param = request.args.get("page", 1)
    try:
        page = int(page_param)
        if page < 1:
            return jsonify({"error": "Page number must be a positive integer greater than or equal to 1"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid page parameter, must be an integer"}), 400

    per_page_param = request.args.get("per_page", 20)
    try:
        per_page = int(per_page_param)
        if per_page < 1:
            return jsonify({"error": "per_page must be a positive integer greater than or equal to 1"}), 400
        per_page = min(per_page, 100)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid per_page parameter, must be an integer"}), 400

    # Legacy limit parameter parsing
    limit_param = request.args.get("limit")
    if limit_param is not None:
        try:
            legacy_limit = int(limit_param)
            if legacy_limit < 1:
                return jsonify({"error": "Limit must be a positive integer"}), 400
            legacy_limit = min(legacy_limit, 100)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid limit parameter, must be an integer"}), 400
    else:
        legacy_limit = 50

    # 2. Parse and validate status filter
    status_filter = request.args.get("status", "").strip().lower()
    if status_filter and status_filter not in VALID_STATUSES:
        return jsonify({
            "error": f"Invalid status filter '{status_filter}'. Allowed values: pending, approved, rejected"
        }), 400

    include_unapproved_requested = request.args.get("include_unapproved", "false").lower() == "true"
    search_query = request.args.get("query", "").strip()

    # 3. Build database query with strict authorization rules applied in SQL before pagination
    query = Resource.query

    if is_admin:
        if status_filter:
            query = query.filter(Resource.status == status_filter)
        elif not include_unapproved_requested:
            query = query.filter(Resource.status == "approved")
    else:
        # Ordinary user authorization rules:
        # Ordinary users must NEVER see pending or rejected resources uploaded by other users.
        if status_filter == "approved":
            query = query.filter(Resource.status == "approved")
        elif status_filter in ("pending", "rejected"):
            # Permitted to view their OWN pending or rejected resources
            query = query.filter(Resource.status == status_filter, Resource.uploaded_by == current_user.id)
        else:
            # Default for ordinary users is approved only
            query = query.filter(Resource.status == "approved")

    if search_query:
        search_filter = f"%{search_query}%"
        query = query.filter(
            or_(
                Resource.title.ilike(search_filter),
                Resource.description.ilike(search_filter),
            )
        )

    # 4. Total count evaluated efficiently at SQL level without loading table into memory
    total = query.count()

    # Deterministic stable ordering: newest first with unique ID tie-breaker
    ordered_query = query.order_by(Resource.created_at.desc(), Resource.id.desc())

    if is_paginated_request:
        offset = (page - 1) * per_page
        resources = ordered_query.offset(offset).limit(per_page).all()
        total_pages = math.ceil(total / per_page) if per_page else 1

        payload = {
            "items": [serialize_resource(r, current_user=current_user) for r in resources],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "has_next": (page < total_pages),
            "has_prev": (page > 1),
        }
        response = jsonify(payload)
    else:
        # Legacy backward-compatible response for callers not specifying page or per_page
        effective_limit = legacy_limit
        resources = ordered_query.limit(effective_limit).all()
        payload = [serialize_resource(r, current_user=current_user) for r in resources]
        response = jsonify(payload)

    # Standard RFC-compliant pagination metadata headers
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Page"] = str(page)
    response.headers["X-Per-Page"] = str(per_page if is_paginated_request else legacy_limit)
    response.headers["X-Total-Pages"] = str(math.ceil(total / per_page) if per_page else 1)

    return response, 200


@resources_bp.route("/<int:resource_id>", methods=["GET"])
@token_required
def get_resource(resource_id):
    """Retrieve single resource details and presigned download URL.
    
    Protected route: requires authentication.
    Non-approved resources (pending or rejected) return 403 Forbidden
    unless requested by the original uploader or an administrator.
    """
    resource = db.session.get(Resource, resource_id)
    if not resource:
        return jsonify({"error": "Resource not found"}), 404

    current_user = g.current_user
    status_val = getattr(resource, "status", None) or ("approved" if resource.approved else "pending")
    is_approved = (status_val == "approved")

    is_authorized = is_approved or (
        getattr(current_user, "is_admin", False) or current_user.id == resource.uploaded_by
    )

    if not is_authorized:
        record_activity_log(
            user_id=current_user.id,
            action="access_denied",
            detail=f"Unauthorized attempt to access {status_val} resource '{resource.title}' (ID {resource.id}) owned by user ID {resource.uploaded_by}",
        )
        msg = "Resource pending approval. Access denied." if status_val == "pending" else f"Resource {status_val}. Access denied."
        return jsonify({"error": msg}), 403

    return jsonify(serialize_resource(resource, current_user=current_user)), 200


@resources_bp.route("", methods=["POST"])
@token_required
def upload_resource():
    """Publish a new digital resource.
    
    Streams file directly to S3 and saves metadata row to PostgreSQL.
    Requires authentication token. Newly created resources start with status='pending' and approved=False.
    """
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    file = request.files.get("file")

    if not title:
        return jsonify({"error": "Title is required"}), 400

    if len(title) > 200:
        return jsonify({"error": "Title must not exceed 200 characters"}), 400

    if not file or not file.filename:
        return jsonify({"error": "Resource file is required"}), 400

    try:
        # Stream file to S3
        s3_key = upload_file_to_s3(
            file_obj=file.stream,
            original_filename=file.filename,
            content_type=file.content_type,
        )

        # Create metadata row in database with initial pending lifecycle state
        resource = Resource(
            title=title,
            description=description,
            s3_key=s3_key,
            uploaded_by=g.current_user.id,
            status="pending",
            approved=False,
        )
        db.session.add(resource)
        db.session.commit()

        # Structured log and ActivityLog
        logger.info(
            f"RESOURCE_PUBLISHED id={resource.id} title='{title}' s3_key='{s3_key}' uploader_id={g.current_user.id}"
        )
        record_activity_log(
            user_id=g.current_user.id,
            action="resource_published",
            detail=f"Resource '{title}' (ID {resource.id}) published with S3 key '{s3_key}'",
        )

        return jsonify(serialize_resource(resource, current_user=g.current_user)), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error publishing resource: {e}")
        return jsonify({"error": f"Failed to publish resource: {str(e)}"}), 500


@resources_bp.route("/<int:resource_id>", methods=["PUT", "PATCH"])
@token_required
def update_resource(resource_id):
    """Update resource metadata (title and description).
    
    Ownership enforcement:
      Only the original uploader or an administrator may update metadata.
      Unauthorized attempts return 403 Forbidden and record an access_denied audit entry.
    """
    resource = db.session.get(Resource, resource_id)
    if not resource:
        return jsonify({"error": "Resource not found"}), 404

    is_owner = (g.current_user.id == resource.uploaded_by)
    is_admin = getattr(g.current_user, "is_admin", False)

    if not is_owner and not is_admin:
        record_activity_log(
            user_id=g.current_user.id,
            action="access_denied",
            detail=f"Unauthorized attempt to update resource '{resource.title}' (ID {resource.id}) owned by user ID {resource.uploaded_by}",
        )
        return jsonify({"error": "Permission denied. You can only update your own resources."}), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be valid JSON"}), 400

    has_update = False
    old_title = resource.title

    if "title" in data:
        new_title = data.get("title")
        if not isinstance(new_title, str) or not new_title.strip():
            return jsonify({"error": "Title cannot be empty"}), 400
        new_title = new_title.strip()
        if len(new_title) > 200:
            return jsonify({"error": "Title must not exceed 200 characters"}), 400
        resource.title = new_title
        has_update = True

    if "description" in data:
        new_desc = data.get("description")
        if new_desc is not None and not isinstance(new_desc, str):
            return jsonify({"error": "Description must be a string"}), 400
        resource.description = new_desc.strip() if new_desc else ""
        has_update = True

    if not has_update:
        return jsonify({"error": "No valid fields provided for update"}), 400

    try:
        db.session.commit()

        logger.info(
            f"RESOURCE_UPDATED id={resource.id} old_title='{old_title}' new_title='{resource.title}' user_id={g.current_user.id}"
        )
        record_activity_log(
            user_id=g.current_user.id,
            action="resource_updated",
            detail=f"Resource '{resource.title}' (ID {resource.id}) updated by '{g.current_user.username}'",
        )

        return jsonify(serialize_resource(resource, current_user=g.current_user)), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating resource {resource_id}: {e}")
        return jsonify({"error": f"Failed to update resource: {str(e)}"}), 500


@resources_bp.route("/<int:resource_id>/approve", methods=["PATCH"])
@admin_required
def approve_resource(resource_id):
    """Admin moderation: approve a resource.
    
    Requires administrator JWT token.
    State transition rules:
      - 'pending' -> 'approved': Allowed.
      - 'approved' -> 'approved': Repeat approval returns 400 Bad Request.
      - 'rejected' -> 'approved': Cannot be silently or accidentally approved;
        requires an explicit administrator reactivation parameter ('reactivate': true).
    """
    resource = db.session.get(Resource, resource_id)
    if not resource:
        return jsonify({"error": "Resource not found"}), 404

    current_status = getattr(resource, "status", None) or ("approved" if resource.approved else "pending")

    if current_status == "approved":
        return jsonify({
            "error": "Resource is already approved",
            "status": "approved",
            "approved": True
        }), 400

    if current_status == "rejected":
        data = request.get_json(silent=True) or {}
        reactivate_flag = data.get("reactivate") is True or request.args.get("reactivate", "").lower() == "true"
        if not reactivate_flag:
            return jsonify({
                "error": "Cannot directly approve a rejected resource. Deliberate reactivation is required (pass 'reactivate': true).",
                "status": "rejected",
                "approved": False
            }), 400

    resource.status = "approved"
    resource.approved = True
    db.session.commit()

    logger.info(
        f"RESOURCE_APPROVED id={resource.id} title='{resource.title}' admin_id={g.current_user.id}"
    )

    record_activity_log(
        user_id=g.current_user.id,
        action="resource_approved",
        detail=f"Resource '{resource.title}' (ID {resource.id}) approved by admin '{g.current_user.username}'",
    )

    return jsonify(serialize_resource(resource, current_user=g.current_user)), 200


@resources_bp.route("/<int:resource_id>/reject", methods=["PATCH"])
@admin_required
def reject_resource(resource_id):
    """Admin moderation: reject a pending resource or revoke approval for an approved resource.
    
    Requires administrator JWT token.
    State transition rules:
      - 'pending' -> 'rejected': Allowed.
      - 'approved' -> 'rejected': Allowed (approval revoked).
      - 'rejected' -> 'rejected': Repeat rejection returns 400 Bad Request.
    """
    resource = db.session.get(Resource, resource_id)
    if not resource:
        return jsonify({"error": "Resource not found"}), 404

    current_status = getattr(resource, "status", None) or ("approved" if resource.approved else "pending")

    if current_status == "rejected":
        return jsonify({
            "error": "Resource is already rejected",
            "status": "rejected",
            "approved": False
        }), 400

    resource.status = "rejected"
    resource.approved = False
    db.session.commit()

    logger.info(
        f"RESOURCE_REJECTED id={resource.id} title='{resource.title}' admin_id={g.current_user.id}"
    )

    record_activity_log(
        user_id=g.current_user.id,
        action="resource_rejected",
        detail=f"Resource '{resource.title}' (ID {resource.id}) rejected by admin '{g.current_user.username}'",
    )

    return jsonify({
        "message": f"Resource #{resource.id} rejected",
        "resource": serialize_resource(resource, current_user=g.current_user)
    }), 200


@resources_bp.route("/<int:resource_id>", methods=["DELETE"])
@token_required
def delete_resource(resource_id):
    """Delete a resource and safely clean up its S3 storage object.
    
    Ownership verification:
      Only the original uploader or an administrator may delete a resource.
      Normal users attempting to delete another user's resource receive 403 Forbidden.
      
    Storage safety strategy:
      1. Storage cleanup is executed first.
      2. If S3 object deletion fails due to an unexpected error, the database transaction
         is aborted and rolled back to prevent leaving orphaned, untracked objects.
      3. Only when S3 cleanup succeeds is the database record deleted and the activity log recorded.
    """
    resource = db.session.get(Resource, resource_id)
    if not resource:
        return jsonify({"error": "Resource not found"}), 404

    is_owner = (g.current_user.id == resource.uploaded_by)
    is_admin = getattr(g.current_user, "is_admin", False)

    if not is_owner and not is_admin:
        record_activity_log(
            user_id=g.current_user.id,
            action="access_denied",
            detail=f"Unauthorized attempt to delete resource '{resource.title}' (ID {resource.id}) owned by user ID {resource.uploaded_by}",
        )
        return jsonify({"error": "Permission denied. You can only delete your own resources."}), 403

    title = resource.title
    s3_key = resource.s3_key

    # Safe storage cleanup: remove object from S3 before deleting the DB record
    try:
        delete_file_from_s3(s3_key)
    except Exception as s3_err:
        logger.error(f"Storage cleanup failed for S3 key '{s3_key}': {s3_err}")
        return jsonify({
            "error": "Failed to clean up storage object. Deletion aborted to prevent orphaned files."
        }), 500

    # Clean up database record only after storage cleanup succeeds
    try:
        db.session.delete(resource)
        db.session.commit()

        logger.info(
            f"RESOURCE_DELETED id={resource_id} title='{title}' s3_key='{s3_key}' user_id={g.current_user.id} is_admin={is_admin}"
        )
        record_activity_log(
            user_id=g.current_user.id,
            action="resource_deleted",
            detail=f"Resource '{title}' (ID {resource_id}) deleted by '{g.current_user.username}'",
        )

        return jsonify({
            "message": "Resource deleted successfully",
            "id": resource_id
        }), 200

    except Exception as db_err:
        db.session.rollback()
        logger.error(f"Database deletion failed for resource {resource_id}: {db_err}")
        return jsonify({"error": "Failed to delete resource database record"}), 500

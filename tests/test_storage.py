import io
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError
from app.storage import upload_file_to_s3, generate_presigned_url, delete_file_from_s3


@patch("app.storage.get_s3_client")
def test_upload_file_to_s3_streams_to_bucket(mock_get_s3, app):
    """Verify upload_file_to_s3 uses upload_fileobj directly without writing to local disk."""
    mock_s3 = MagicMock()
    mock_get_s3.return_value = mock_s3

    with app.app_context():
        file_content = io.BytesIO(b"Hello CloudOps S3 Content")
        s3_key = upload_file_to_s3(file_content, "sample_guide.txt", content_type="text/plain")

        assert s3_key.startswith("resources/")
        assert s3_key.endswith("_sample_guide.txt")
        mock_s3.upload_fileobj.assert_called_once()
        args, kwargs = mock_s3.upload_fileobj.call_args
        assert args[0] == file_content
        assert args[1] == "test-sentinel-bucket"
        assert args[2] == s3_key
        assert kwargs["ExtraArgs"] == {"ContentType": "text/plain"}


@patch("app.storage.get_s3_client")
def test_generate_presigned_url(mock_get_s3, app):
    """Verify presigned download URL generation."""
    mock_s3 = MagicMock()
    mock_s3.generate_presigned_url.return_value = "https://s3.amazonaws.com/test-bucket/resources/guide.pdf"
    mock_get_s3.return_value = mock_s3

    with app.app_context():
        url = generate_presigned_url("resources/guide.pdf", expires_in=1800)
        assert url == "https://s3.amazonaws.com/test-bucket/resources/guide.pdf"
        mock_s3.generate_presigned_url.assert_called_once_with(
            "get_object",
            Params={"Bucket": "test-sentinel-bucket", "Key": "resources/guide.pdf"},
            ExpiresIn=1800,
        )


@patch("app.storage.get_s3_client")
def test_delete_file_from_s3_success(mock_get_s3, app):
    """Verify delete_file_from_s3 calls delete_object with correct bucket and key."""
    mock_s3 = MagicMock()
    mock_get_s3.return_value = mock_s3

    with app.app_context():
        res = delete_file_from_s3("resources/sample.pdf")
        assert res is True
        mock_s3.delete_object.assert_called_once_with(
            Bucket="test-sentinel-bucket",
            Key="resources/sample.pdf"
        )


@patch("app.storage.get_s3_client")
def test_delete_file_from_s3_handles_not_found(mock_get_s3, app):
    """Verify NoSuchKey error is gracefully handled as already deleted."""
    mock_s3 = MagicMock()
    error_response = {"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}}
    mock_s3.delete_object.side_effect = ClientError(error_response, "DeleteObject")
    mock_get_s3.return_value = mock_s3

    with app.app_context():
        res = delete_file_from_s3("resources/missing.pdf")
        assert res is True


@patch("app.storage.get_s3_client")
def test_delete_file_from_s3_raises_on_unexpected_error(mock_get_s3, app):
    """Verify unexpected ClientError is re-raised to prevent orphaned DB deletions."""
    mock_s3 = MagicMock()
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
    mock_s3.delete_object.side_effect = ClientError(error_response, "DeleteObject")
    mock_get_s3.return_value = mock_s3

    with app.app_context():
        with pytest.raises(ClientError):
            delete_file_from_s3("resources/error.pdf")

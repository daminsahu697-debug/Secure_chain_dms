import json
from unittest.mock import AsyncMock, patch
import httpx
import pytest

from app.services.ocr_client import OCRClient, FORGERY_THRESHOLD


@pytest.fixture
def client():
    return OCRClient(base_url="http://mock-ocr-service:8000", timeout=5.0)


@pytest.mark.anyio
async def test_successful_ocr_scan(client):
    mock_ocr_json = {
        "records": [
            {
                "district": "Patna",
                "police_station": "Kotwali",
                "fir_number": "FIR-2026-099",
                "fir_description_english": "Alleged theft of official evidence document.",
            }
        ],
        "sensitivity": {
            "suggested_sensitivity_tier": "High",
            "suggested_quorum": "3-of-5 approvers required",
            "matched_high_risk_terms": ["evidence", "theft"],
            "matched_medium_risk_terms": ["fir"],
            "note": "High risk evidence document",
        },
        "worm_log": [
            {
                "document_id": "doc-uuid-1234",
                "forensic_alert_level": "HIGH-ALERT: SUSPECTED FORGERY",
                "pixel_anomaly_coefficient": "0.8250",
            }
        ],
        "ela_preview_base64_png": "iVBORw0KGgoAAAANSUhEUgAA",
    }

    mock_req = httpx.Request("POST", "http://mock-ocr-service:8000/api/case/submit")
    mock_response = httpx.Response(200, json=mock_ocr_json, request=mock_req)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        res = await client.scan_document(
            file_bytes=b"%PDF-mock-bytes",
            filename="fir_test.pdf",
            officer_id="POL-IO-001",
            case_mode="Register New FIR (first time)",
            is_fir=True,
        )

        assert res["is_online"] is True
        assert res["suggested_sensitivity"] == "HIGH"
        assert res["tamper_score"] == 0.8250
        assert res["forgery_detected"] is True
        assert res["forensic_alert_level"] == "HIGH-ALERT: SUSPECTED FORGERY"
        assert "evidence" in res["matched_high_risk_terms"]
        assert len(res["ocr_records"]) == 1
        assert res["ela_preview_base64_png"] == "iVBORw0KGgoAAAANSUhEUgAA"


@pytest.mark.anyio
async def test_ocr_service_offline_connection_error(client):
    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        res = await client.scan_document(
            file_bytes=b"dummy bytes",
            filename="doc.jpg",
        )

        assert res["is_online"] is False
        assert res["forensic_alert_level"] == "SERVICE_OFFLINE"
        assert res["suggested_sensitivity"] == "MEDIUM"
        assert res["tamper_score"] == 0.0
        assert res["forgery_detected"] is False
        assert res["ocr_records"] == []


@pytest.mark.anyio
async def test_ocr_service_timeout(client):
    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.TimeoutException("Read timeout after 90s")

        res = await client.scan_document(
            file_bytes=b"dummy bytes",
            filename="large_doc.pdf",
        )

        assert res["is_online"] is False
        assert res["forensic_alert_level"] == "SERVICE_TIMEOUT"
        assert res["suggested_sensitivity"] == "MEDIUM"
        assert res["tamper_score"] == 0.0


@pytest.mark.anyio
async def test_ocr_service_http_500_error(client):
    mock_req = httpx.Request("POST", "http://mock-ocr-service:8000/api/case/submit")
    mock_response = httpx.Response(500, text="Internal Server Error", request=mock_req)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        res = await client.scan_document(
            file_bytes=b"dummy bytes",
            filename="doc.pdf",
        )

        assert res["is_online"] is False
        assert res["forensic_alert_level"] == "HTTP_ERROR_500"
        assert res["suggested_sensitivity"] == "MEDIUM"


@pytest.mark.anyio
async def test_ocr_service_malformed_json(client):
    mock_req = httpx.Request("POST", "http://mock-ocr-service:8000/api/case/submit")
    mock_response = httpx.Response(200, text="Not a valid JSON {", request=mock_req)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        res = await client.scan_document(
            file_bytes=b"dummy bytes",
            filename="doc.pdf",
        )

        assert res["is_online"] is False
        assert res["forensic_alert_level"] == "MALFORMED_RESPONSE"


@pytest.mark.anyio
async def test_sensitivity_mapping_and_tamper_score_extraction(client):
    mock_ocr_json = {
        "records": [],
        "sensitivity": {
            "suggested_sensitivity_tier": "Low",
            "suggested_quorum": "1 checker required",
        },
        "worm_log": [
            {
                "forensic_alert_level": "INTEGRITY CHECK PASSED",
                "pixel_anomaly_coefficient": "0.1500",
            },
            {
                "forensic_alert_level": "MID-LEVEL ANOMALY DETECTED",
                "pixel_anomaly_coefficient": "0.4500",
            },
        ],
    }

    mock_req = httpx.Request("POST", "http://mock-ocr-service:8000/api/case/submit")
    mock_response = httpx.Response(200, json=mock_ocr_json, request=mock_req)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        res = await client.scan_document(
            file_bytes=b"sample bytes",
            filename="routine_note.png",
        )

        assert res["is_online"] is True
        assert res["suggested_sensitivity"] == "LOW"
        assert res["tamper_score"] == 0.4500
        assert res["forgery_detected"] is False
        assert res["forensic_alert_level"] == "MID-LEVEL ANOMALY DETECTED"

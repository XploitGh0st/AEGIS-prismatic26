"""
PCAP API — upload PCAP files for automated threat analysis.

Endpoints:
- POST /api/v1/pcap/upload — upload a .pcap/.pcapng file
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.core.logging import get_logger
from app.services.pcap_service import analyze_pcap, save_uploaded_pcap
from app.models.raw_alert import RawAlert
from app.models.normalized_alert import NormalizedAlert
from app.services.normalization_service import normalize_raw_alert
from app.services.correlation_service import correlate_alert
from app.utils.datetime import parse_iso

log = get_logger("pcap_api")
router = APIRouter(prefix="/pcap", tags=["pcap"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Upload a PCAP file for automated threat analysis.

    The file is parsed using deep packet inspection to extract:
    - Port scan patterns
    - SSH brute force attempts
    - DNS anomalies (DGA, tunneling)
    - Suspicious payload patterns
    - HTTP attack signatures
    - Data exfiltration indicators

    Each finding is converted to an alert and processed through the
    full AEGIS pipeline: Normalize → Correlate → Score → Classify.
    """
    # Validate filename
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Read file content
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB")

    # Save file
    file_path, pcap_id = await save_uploaded_pcap(file.filename, content)

    # Analyze PCAP
    try:
        canonical_alerts = analyze_pcap(file_path)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not canonical_alerts:
        return {
            "pcap_id": pcap_id,
            "filename": file.filename,
            "file_size_bytes": len(content),
            "status": "complete",
            "alerts_generated": 0,
            "incidents_created": [],
            "message": "No security-relevant findings in the PCAP file",
        }

    # Feed each alert through the AEGIS pipeline directly
    # (bypass the standard ingest to avoid queue/dedup issues)
    incident_ids = set()
    alert_count = 0

    for canonical in canonical_alerts:
        try:
            # Create raw alert directly with unique ID
            raw_id = uuid.uuid4()
            event_time = canonical.event_time

            payload_dict = {
                "event_time": event_time.isoformat(),
                "category": canonical.category,
                "event_name": canonical.event_name,
                "severity": canonical.severity,
                "confidence": canonical.confidence,
                "user_name": canonical.user_name,
                "host_name": canonical.host_name,
                "source_ip": canonical.source_ip,
                "destination_ip": canonical.destination_ip,
                "source_port": canonical.source_port,
                "destination_port": canonical.destination_port,
                "mitre_technique_ids": canonical.mitre_technique_ids,
                "mitre_tactic": canonical.mitre_tactic,
                "description": canonical.description,
                "risk_flags": canonical.risk_flags,
                "raw_command": canonical.raw_command,
                "session_id": canonical.session_id,
                "extra_data": canonical.extra_data,
                "pcap_id": pcap_id,
            }

            # Create raw alert with unique external_alert_id
            raw_alert = RawAlert(
                id=raw_id,
                source_family=canonical.source_family,
                source_type=canonical.source_type,
                external_alert_id=f"pcap_{pcap_id}_{str(raw_id)[:8]}",
                event_time=event_time,
                payload=payload_dict,
                processing_status="pending",
            )
            session.add(raw_alert)
            await session.flush()

            # Normalize
            normalized = await normalize_raw_alert(session, str(raw_id))
            if normalized:
                await session.flush()

                # Correlate
                incident = await correlate_alert(session, str(normalized.id))
                await session.flush()
                incident_ids.add(str(incident.id))

            alert_count += 1

        except Exception as e:
            log.error("pcap_alert_pipeline_error", error=str(e), alert_index=alert_count)
            # Rollback just this alert's partial work
            try:
                await session.rollback()
            except Exception:
                pass
            continue

    log.info(
        "pcap_upload_complete",
        pcap_id=pcap_id,
        alerts=alert_count,
        incidents=len(incident_ids),
    )

    return {
        "pcap_id": pcap_id,
        "filename": file.filename,
        "file_size_bytes": len(content),
        "status": "complete",
        "alerts_generated": alert_count,
        "incidents_created": list(incident_ids),
        "message": f"PCAP analyzed: {alert_count} alerts generated, {len(incident_ids)} incident(s) created/updated",
    }

"""Debug script to test alert ingestion and see full errors."""
import asyncio
import traceback
from app.core.database import async_session_factory, init_db
from app.schemas.alert_ingest import AlertIngestRequest
from app.services.ingestion_service import ingest_alert
from app.services.normalization_service import normalize_raw_alert
from app.services.correlation_service import correlate_alert

async def main():
    await init_db()
    async with async_session_factory() as session:
        # Test single CVE alert
        alert_data = {
            "source_family": "ids",
            "source_type": "pcap_analysis",
            "external_alert_id": "test_cve_001",
            "event_time": "2026-04-09T11:30:00.000Z",
            "payload": {
                "event_type": "jndi_injection",
                "timestamp": "2026-04-09T11:30:00.000Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.1.50",
                "src_port": 41337,
                "dst_port": 8080,
                "description": "Log4Shell JNDI injection detected"
            }
        }
        try:
            request = AlertIngestRequest(**alert_data)
            print(f"1. AlertIngestRequest created OK: {request.source_family}/{request.source_type}")
        except Exception as e:
            print(f"1. FAILED creating AlertIngestRequest: {e}")
            traceback.print_exc()
            return

        try:
            raw_alert = await ingest_alert(session, request)
            await session.flush()
            print(f"2. Raw alert ingested OK: {raw_alert.id}")
        except Exception as e:
            print(f"2. FAILED ingesting: {e}")
            traceback.print_exc()
            return

        try:
            normalized = await normalize_raw_alert(session, str(raw_alert.id))
            if normalized:
                await session.flush()
                print(f"3. Normalized OK: {normalized.event_name} | {normalized.severity} | {normalized.source_ip}")
            else:
                print("3. Normalization returned None")
        except Exception as e:
            print(f"3. FAILED normalizing: {e}")
            traceback.print_exc()
            return

        try:
            incident = await correlate_alert(session, str(normalized.id))
            await session.flush()
            print(f"4. Correlated OK: {incident.title} | {incident.classification} | {incident.severity}")
        except Exception as e:
            print(f"4. FAILED correlating: {e}")
            traceback.print_exc()
            return

        await session.commit()
        print("\nSUCCESS: Full pipeline completed!")

asyncio.run(main())

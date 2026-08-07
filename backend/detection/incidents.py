"""
Incident Management (Attack Timeline)
=====================================
Aggregates related alerts into incidents to reconstruct the attack timeline.
An incident groups alerts by source IP or target IP within a specific timeframe.
"""

from __future__ import annotations

import time
import time
from typing import Any

from backend.db.database import get_session, Alert, Incident
from backend.threat.mitre import get_mitre_mapping

def correlate_alerts_into_incidents() -> None:
    """
    Background job that looks for unassigned alerts and groups them into incidents.
    Groups by source_ip within a 1-hour window.
    """
    session = get_session()
    try:
        # Find alerts not yet part of an incident
        unassigned = session.query(Alert).filter(Alert.incident_id.is_(None)).all()
        if not unassigned:
            return

        # Simple correlation: group by src_ip
        groups = {}
        for alert in unassigned:
            if not alert.src_ip:
                continue
            if alert.src_ip not in groups:
                groups[alert.src_ip] = []
            groups[alert.src_ip].append(alert)

        for src_ip, alerts in groups.items():
            if not alerts:
                continue

            alerts.sort(key=lambda a: a.timestamp)
            
            # Check if there's an active incident for this IP
            active_incident = session.query(Incident).filter(
                Incident.status != "resolved",
                Incident.title.like(f"%{src_ip}%")
            ).first()

            if not active_incident:
                # Determine initial severity
                max_score = max((a.cvss_score for a in alerts if a.cvss_score), default=0.0)
                severity = "low"
                if max_score >= 9.0: severity = "critical"
                elif max_score >= 7.0: severity = "high"
                elif max_score >= 4.0: severity = "medium"

                # Generate ID
                count = session.query(Incident).count()
                inc_id = f"INC-{(count + 1):04d}"

                active_incident = Incident(
                    incident_id=inc_id,
                    title=f"Attack Campaign originating from {src_ip}",
                    description=f"Multiple security alerts correlated to source IP {src_ip}.",
                    severity=severity,
                    status="new",
                    priority=1 if severity == "critical" else 2 if severity == "high" else 3,
                    alert_ids=[]
                )
                session.add(active_incident)
                session.commit() # Commit to get the ID

            # Append alerts to incident
            # Append alerts to incident
            alert_ids = list(active_incident.alert_ids or [])
            evidence = list(active_incident.evidence or [])
            
            for alert in alerts:
                alert.incident_id = active_incident.id
                if alert.id not in alert_ids:
                    alert_ids.append(alert.id)
                    
                    # Look up MITRE mapping for this alert type
                    mapping = get_mitre_mapping(alert.title)
                    if mapping:
                        # Add to evidence if not already present
                        is_present = any(e.get('type') == 'mitre_tactic' and e.get('data', {}).get('technique') == mapping['technique'] for e in evidence)
                        if not is_present:
                            evidence.append({
                                "type": "mitre_tactic",
                                "timestamp": time.time(),
                                "data": mapping
                            })
            
            active_incident.alert_ids = alert_ids
            active_incident.evidence = evidence
            session.commit()

            print(f"[Incidents] Correlated {len(alerts)} alerts into {active_incident.incident_id}")

    except Exception as e:
        print(f"[Incidents] Correlation error: {e}")
    finally:
        session.close()

def generate_attack_timeline(incident_id: int) -> dict[str, Any]:
    """Reconstruct a narrative timeline for an incident."""
    session = get_session()
    try:
        incident = session.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return {"error": "Incident not found"}

        alerts = session.query(Alert).filter(Alert.id.in_(incident.alert_ids)).order_by(Alert.timestamp.asc()).all()
        
        timeline = []
        tactics_seen = set()

        for a in alerts:
            stage = "Unknown"
            if a.mitre_tactic:
                stage = a.mitre_tactic
                tactics_seen.add(a.mitre_tactic)
            
            timeline.append({
                "timestamp": a.timestamp,
                "event": a.title,
                "description": a.description,
                "stage": stage,
                "severity": a.severity,
                "source": a.source
            })

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "status": incident.status,
            "severity": incident.severity,
            "attack_stages": list(tactics_seen),
            "timeline": timeline,
            "alert_count": len(alerts)
        }
    finally:
        session.close()

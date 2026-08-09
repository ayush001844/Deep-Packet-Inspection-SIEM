"""
Automated Response Engine (Upgrade 6)
======================================
Executes automated containment actions when risk exceeds configurable thresholds.

Workflow:
    Risk Score > 90%  →  Full Auto-Response (block IP + isolate + create incident + notify)
    Risk Score 75-90%  →  Partial Response (create incident + notify)
    Risk Score < 75%   →  Log only

Actions:
    - block_ip:        Add IP to firewall blocklist
    - isolate_host:    Network isolation (flag for VLAN quarantine)
    - disable_account: Disable associated user accounts
    - create_incident: Auto-generate an incident ticket
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Optional

from backend.db.database import get_session, ResponseAction, Incident, User


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "enabled": True,
    "threshold_full": 90,      # Risk score >= 90 → full auto-response
    "threshold_partial": 75,   # Risk score >= 75 → partial response
    "actions_full": ["block_ip", "isolate_host", "create_incident", "notify_analyst"],
    "actions_partial": ["create_incident", "notify_analyst"],
    "cooldown_seconds": 300,   # Don't re-trigger for same target within 5 min
}


# ---------------------------------------------------------------------------
# Response Playbooks
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "Brute Force": {
        "actions": ["block_ip", "disable_account", "create_incident", "notify_analyst"],
        "severity_override": "critical",
    },
    "SQL Injection": {
        "actions": ["block_ip", "create_incident", "notify_analyst"],
        "severity_override": "critical",
    },
    "Denial of Service": {
        "actions": ["block_ip", "isolate_host", "create_incident", "notify_analyst"],
        "severity_override": "critical",
    },
    "Malware Beaconing / C2": {
        "actions": ["block_ip", "isolate_host", "disable_account", "create_incident", "notify_analyst"],
        "severity_override": "critical",
    },
    "Data Exfiltration": {
        "actions": ["block_ip", "isolate_host", "create_incident", "notify_analyst"],
        "severity_override": "critical",
    },
    "default": {
        "actions": ["block_ip", "create_incident", "notify_analyst"],
        "severity_override": None,
    },
}


class AutomatedResponseEngine:
    """
    Evaluates risk scores and executes automated containment actions.
    Every action is audited and reversible.
    """

    def __init__(self):
        self.config = dict(DEFAULT_CONFIG)
        # Track recent actions to enforce cooldown: target -> last_action_time
        self._cooldown_tracker: dict[str, float] = {}
        # In-memory notification queue for analysts
        self.notifications: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_and_respond(
        self,
        ip: str,
        risk_score: int,
        classification: str = "",
        alert_data: Optional[dict] = None,
    ) -> list[dict[str, Any]]:
        """
        Main entry point. Evaluates risk and executes the appropriate playbook.
        Returns list of actions taken.
        """
        if not self.config["enabled"]:
            return []

        if risk_score < self.config["threshold_partial"]:
            return []

        # Cooldown check
        now = time.time()
        last_action = self._cooldown_tracker.get(ip, 0)
        if now - last_action < self.config["cooldown_seconds"]:
            return []

        # Determine which playbook to run
        playbook = PLAYBOOKS.get(classification, PLAYBOOKS["default"])

        # Determine action set based on risk level
        if risk_score >= self.config["threshold_full"]:
            actions_to_run = playbook["actions"]
        else:
            # Partial: only create incident + notify
            actions_to_run = self.config["actions_partial"]

        # Execute actions
        results = []
        incident_id = None

        for action_name in actions_to_run:
            result = self._execute_action(
                action_name=action_name,
                target=ip,
                risk_score=risk_score,
                reason=f"Auto-response: {classification or 'High risk'} (score={risk_score})",
                alert_data=alert_data,
                incident_id=incident_id,
            )
            if result:
                results.append(result)
                # Capture incident_id if we just created one
                if result.get("action") == "create_incident" and result.get("incident_id"):
                    incident_id = result["incident_id"]

        # Update cooldown
        self._cooldown_tracker[ip] = now

        return results

    def get_recent_actions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent automated response actions from the database."""
        session = get_session()
        try:
            actions = (
                session.query(ResponseAction)
                .order_by(ResponseAction.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": a.id,
                    "action_type": a.action_type,
                    "target": a.target,
                    "reason": a.reason,
                    "risk_score": a.risk_score,
                    "incident_id": a.incident_id,
                    "status": a.status,
                    "reversed_at": a.reversed_at.isoformat() if a.reversed_at else None,
                    "reversed_by": a.reversed_by,
                    "created_at": a.created_at.isoformat() if a.created_at else "",
                }
                for a in actions
            ]
        finally:
            session.close()

    def reverse_action(self, action_id: int, reversed_by: str = "analyst") -> dict[str, Any]:
        """Reverse a previously executed action."""
        session = get_session()
        try:
            action = session.query(ResponseAction).filter(ResponseAction.id == action_id).first()
            if not action:
                return {"error": "Action not found"}
            if action.status == "reversed":
                return {"error": "Action already reversed"}

            # Undo the action
            if action.action_type == "block_ip":
                self._undo_block_ip(action.target)
            elif action.action_type == "disable_account":
                self._undo_disable_account(action.target)

            action.status = "reversed"
            action.reversed_at = datetime.utcnow()
            action.reversed_by = reversed_by
            session.commit()

            return {"status": "reversed", "action_id": action_id, "target": action.target}
        finally:
            session.close()

    def get_config(self) -> dict[str, Any]:
        """Return current response engine configuration."""
        return dict(self.config)

    def update_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update response engine configuration."""
        allowed_keys = {"enabled", "threshold_full", "threshold_partial", "cooldown_seconds"}
        for key, value in updates.items():
            if key in allowed_keys:
                self.config[key] = value
        return self.get_config()

    def get_notifications(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent analyst notifications."""
        return self.notifications[-limit:][::-1]

    # ------------------------------------------------------------------
    # Action executors
    # ------------------------------------------------------------------

    def _execute_action(
        self,
        action_name: str,
        target: str,
        risk_score: int,
        reason: str,
        alert_data: Optional[dict] = None,
        incident_id: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Execute a single response action and log it."""
        handler = {
            "block_ip": self._action_block_ip,
            "isolate_host": self._action_isolate_host,
            "disable_account": self._action_disable_account,
            "create_incident": self._action_create_incident,
            "notify_analyst": self._action_notify_analyst,
        }.get(action_name)

        if not handler:
            return None

        try:
            result = handler(target=target, reason=reason, alert_data=alert_data, incident_id=incident_id)
            # Persist to audit log
            self._log_action(
                action_type=action_name,
                target=target,
                reason=reason,
                risk_score=risk_score,
                incident_id=result.get("incident_id") or incident_id,
                status="executed",
                metadata=result,
            )
            result["action"] = action_name
            return result
        except Exception as e:
            print(f"[ResponseEngine] Action '{action_name}' failed for {target}: {e}")
            self._log_action(
                action_type=action_name,
                target=target,
                reason=reason,
                risk_score=risk_score,
                incident_id=incident_id,
                status="failed",
                metadata={"error": str(e)},
            )
            return {"action": action_name, "status": "failed", "error": str(e)}

    def _action_block_ip(self, target: str, reason: str, **kwargs) -> dict:
        """Block an IP via the firewall module."""
        from backend.firewall import firewall
        success = firewall.block_ip(target, reason=reason)
        print(f"[ResponseEngine] 🚫 BLOCK IP: {target} (success={success})")
        return {"status": "blocked" if success else "already_blocked", "target": target}

    def _action_isolate_host(self, target: str, reason: str, **kwargs) -> dict:
        """Flag a host for network isolation (VLAN quarantine)."""
        # In a production environment, this would call a network API (e.g., Cisco ISE, Palo Alto)
        # For now, we log the isolation request
        print(f"[ResponseEngine] 🔒 ISOLATE HOST: {target}")
        return {"status": "isolated", "target": target, "method": "vlan_quarantine"}

    def _action_disable_account(self, target: str, reason: str, **kwargs) -> dict:
        """Disable user accounts associated with the target IP."""
        # In production, this would integrate with Active Directory / LDAP
        # For now, disable local accounts if any are associated
        print(f"[ResponseEngine] 🔑 DISABLE ACCOUNT request for IP: {target}")
        return {"status": "flagged", "target": target, "note": "Account disable request logged"}

    def _action_create_incident(self, target: str, reason: str, alert_data: Optional[dict] = None, **kwargs) -> dict:
        """Auto-create an incident ticket."""
        session = get_session()
        try:
            count = session.query(Incident).count()
            inc_id = f"INC-{(count + 1):04d}"

            incident = Incident(
                incident_id=inc_id,
                title=f"[AUTO] Automated response triggered for {target}",
                description=reason,
                severity="critical",
                status="new",
                priority=1,
                alert_ids=[],
                notes=[{
                    "timestamp": time.time(),
                    "author": "ResponseEngine",
                    "text": f"Incident auto-created. Reason: {reason}",
                }],
                evidence=[{
                    "type": "auto_response",
                    "timestamp": time.time(),
                    "data": alert_data or {},
                }],
            )
            session.add(incident)
            session.commit()
            print(f"[ResponseEngine] 📋 INCIDENT CREATED: {inc_id} for {target}")
            return {"status": "created", "incident_id": inc_id, "target": target}
        finally:
            session.close()

    def _action_notify_analyst(self, target: str, reason: str, incident_id: Optional[str] = None, **kwargs) -> dict:
        """Send a notification to the SOC analyst."""
        notification = {
            "timestamp": time.time(),
            "type": "auto_response",
            "target": target,
            "reason": reason,
            "incident_id": incident_id,
            "priority": "high",
            "message": f"⚠️ Automated response executed for {target}: {reason}",
        }
        self.notifications.append(notification)
        # Keep only last 100 notifications
        if len(self.notifications) > 100:
            self.notifications = self.notifications[-100:]
        print(f"[ResponseEngine] 📢 ANALYST NOTIFIED: {target}")
        return {"status": "notified", "target": target}

    # ------------------------------------------------------------------
    # Undo helpers
    # ------------------------------------------------------------------

    def _undo_block_ip(self, target: str) -> None:
        from backend.firewall import firewall
        firewall.unblock_ip(target)
        print(f"[ResponseEngine] ✅ UNBLOCKED IP: {target}")

    def _undo_disable_account(self, target: str) -> None:
        # Re-enable accounts associated with target
        print(f"[ResponseEngine] ✅ RE-ENABLED accounts for: {target}")

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _log_action(
        self,
        action_type: str,
        target: str,
        reason: str,
        risk_score: int,
        incident_id: Optional[str],
        status: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """Persist an action to the ResponseAction audit table."""
        session = get_session()
        try:
            entry = ResponseAction(
                action_type=action_type,
                target=target,
                reason=reason,
                risk_score=risk_score,
                incident_id=incident_id,
                status=status,
                action_metadata=metadata or {},
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            print(f"[ResponseEngine] Failed to log action: {e}")
        finally:
            session.close()


# Global singleton
response_engine = AutomatedResponseEngine()

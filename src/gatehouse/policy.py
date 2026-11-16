"""Authorization decisions. Deny unless every condition holds."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .store import Store
from .vault import Credential


@dataclass
class Decision:
    allowed: bool
    reason: str
    grant_id: str | None = None
    kind: str | None = None


def authorize(store: Store, agent_id: str, cred: Credential, origin: str, boot_id: str,
              now: float | None = None) -> Decision:
    """May `agent_id` sign in to `cred` at `origin` right now?

    The origin must be approved on the credential AND listed on the grant, so
    neither an edited grant nor an edited credential can widen access alone.
    """
    now = time.time() if now is None else now
    if store.logins_disabled():
        return Decision(False, "logins_disabled")
    agent = store.agent(agent_id)
    if agent is None or agent["revoked_at"] is not None:
        return Decision(False, "agent_revoked")
    if origin not in cred.origins:
        return Decision(False, "origin_not_approved")
    for g in store.grants(agent_id=agent_id, credential_id=cred.id, active_only=True):
        if g["operation"] != "sign_in" or origin not in json.loads(g["origins"]):
            continue
        if g["kind"] == "once" and g["used_count"] > 0:
            continue
        if g["kind"] == "session" and g["boot_id"] != boot_id:
            continue
        if g["kind"] == "until" and (g["expires_at"] is None or g["expires_at"] <= now):
            continue
        return Decision(True, "granted", g["id"], g["kind"])
    return Decision(False, "no_grant")


def visible_accounts(store: Store, agent_id: str, creds: list[Credential], boot_id: str) -> list[dict]:
    """Accounts an agent may see: only those it can currently sign in to."""
    out = []
    for c in creds:
        allowed = [o for o in c.origins if authorize(store, agent_id, c, o, boot_id).allowed]
        if allowed:
            meta = c.public()
            meta["origins"] = allowed
            out.append(meta)
    return out

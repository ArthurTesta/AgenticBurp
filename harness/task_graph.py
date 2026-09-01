"""
Penetration task graph -- the closed loop as an explicit dependency DAG.

Until now the engagement's escalation work lived in a FLAT queue: a list of
"things to do" with no notion that one depends on another. But a real
engagement is a dependency graph -- "test the admin API" is *blocked* until you
"obtain an admin session," which is *blocked* until you "confirm the auth
bypass." The AppSecSanta 2026 survey names this directly (VulnBot's
"penetration task graph: nodes are tasks, edges are dependencies"); it is the
structural upgrade that turns our implicit finding->identity->new-surface cycle
into an inspectable object the driver can walk correctly.

A Task is READY only when every task it depends_on is done. The driver surfaces
ready tasks; blocked tasks are shown with the prerequisite they are waiting on
(often "needs human/credentials"), so nothing is silently stuck and the operator
sees exactly what would unlock the next move. Marking a task done automatically
re-evaluates the graph, promoting any dependents whose prerequisites are now all
satisfied.

Pure data + graph logic -- deterministic, serializable, no LLM. It replaces the
old pending_actions queue as the engagement state's work model.
"""
from __future__ import annotations
from dataclasses import dataclass, field

# Task lifecycle. Following VulnBot's PTG, a finished task carries a SUCCESS axis:
# a task that finished but FAILED is preserved (not silently dropped) and, crucially,
# does NOT satisfy dependents -- a prerequisite must actually SUCCEED to unblock what
# depends on it ("test admin" stays blocked if "obtain admin session" failed). Failed
# tasks are surfaced for reanalysis rather than retried blindly.
READY = "ready"       # all prerequisites succeeded -> actionable now
BLOCKED = "blocked"   # waiting on a prerequisite (see depends_on / needs)
DONE = "done"         # finished, succeeded
FAILED = "failed"     # finished, did not succeed -> flagged for reanalysis
SKIPPED = "skipped"   # deliberately not doing it

# Only these satisfy a dependency (let a dependent become ready).
_SATISFYING = (DONE, SKIPPED)


@dataclass
class Task:
    id: str
    kind: str            # analyze | confirm | recrawl_area | recrawl_as_derived | obtain | manual
    target: str          # endpoint key / area / identity
    reason: str = ""
    status: str = READY
    depends_on: list = field(default_factory=list)  # task ids that must be DONE first
    needs: str = ""      # human-readable prerequisite when blocked (e.g. "admin credentials")
    source: str = ""     # the finding/url that spawned it
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "target": self.target, "reason": self.reason,
                "status": self.status, "depends_on": self.depends_on, "needs": self.needs,
                "source": self.source, "meta": self.meta}

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        return cls(id=d["id"], kind=d.get("kind", ""), target=d.get("target", ""),
                   reason=d.get("reason", ""), status=d.get("status", READY),
                   depends_on=list(d.get("depends_on", [])), needs=d.get("needs", ""),
                   source=d.get("source", ""), meta=d.get("meta", {}) or {})


def make_id(kind: str, target: str) -> str:
    return f"{kind}:{target}"


@dataclass
class TaskGraph:
    tasks: dict = field(default_factory=dict)   # id -> Task

    def add(self, kind: str, target: str, *, reason: str = "", depends_on: list | None = None,
            needs: str = "", source: str = "", meta: dict | None = None) -> Task:
        """Add a task (idempotent by id = kind:target). If it already exists it is
        returned unchanged unless it was DONE/SKIPPED, in which case a re-add is
        ignored -- a finished task is not silently resurrected. New tasks start
        BLOCKED when they have unmet dependencies, READY otherwise."""
        tid = make_id(kind, target)
        existing = self.tasks.get(tid)
        if existing is not None:
            return existing
        deps = list(depends_on or [])
        status = BLOCKED if any(self._pending(d) for d in deps) or needs else READY
        t = Task(id=tid, kind=kind, target=target, reason=reason, status=status,
                 depends_on=deps, needs=needs, source=source, meta=meta or {})
        self.tasks[tid] = t
        return t

    def _pending(self, dep_id: str) -> bool:
        """A dependency is still 'pending' (blocks its dependents) unless it has
        actually SUCCEEDED. A missing or FAILED dependency keeps dependents
        blocked -- you can't test what you never managed to unlock."""
        d = self.tasks.get(dep_id)
        return d is None or d.status not in _SATISFYING

    def mark(self, task_id: str, status: str) -> None:
        t = self.tasks.get(task_id)
        if t is None:
            return
        t.status = status
        self._unlock()  # a success may promote dependents; a failure never does

    def failed(self) -> list:
        return [t for t in self.tasks.values() if t.status == FAILED]

    def mark_by(self, kind: str, target: str, status: str = DONE) -> None:
        self.mark(make_id(kind, target), status)

    def _unlock(self) -> None:
        """Promote BLOCKED tasks whose dependencies are now all satisfied. A task
        with a `needs` note stays blocked until it is explicitly resolved (its
        prerequisite is a human/credential input, not another task)."""
        for t in self.tasks.values():
            if t.status == BLOCKED and not t.needs and not any(self._pending(d) for d in t.depends_on):
                t.status = READY

    def resolve_need(self, task_id: str) -> None:
        """Clear a task's human/credential prerequisite, then re-evaluate."""
        t = self.tasks.get(task_id)
        if t is not None:
            t.needs = ""
            if not any(self._pending(d) for d in t.depends_on):
                t.status = READY

    def ready(self) -> list:
        return [t for t in self.tasks.values() if t.status == READY]

    def blocked(self) -> list:
        return [t for t in self.tasks.values() if t.status == BLOCKED]

    def to_dict(self) -> dict:
        return {"tasks": {tid: t.to_dict() for tid, t in self.tasks.items()}}

    @classmethod
    def from_dict(cls, d: dict) -> "TaskGraph":
        g = cls()
        for tid, td in (d.get("tasks", {}) or {}).items():
            g.tasks[tid] = Task.from_dict(td)
        return g

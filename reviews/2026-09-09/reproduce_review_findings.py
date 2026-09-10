"""Review-only, offline reproductions. No target traffic or product modifications."""
from pathlib import Path
import ast
import asyncio
import importlib.util
import json
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.review-deps'))
sys.path.insert(0, str(ROOT / 'harness'))

import coverage_tracker
import confirmation_gate
import engagement
import identity_compare
from safety_gate import GatedAsyncClient, SafetyGate, SafetyGateConfig

results = {}
results['gated_client_convenience_methods'] = {
    name: hasattr(GatedAsyncClient, name) for name in ('request', 'post', 'get')}
results['provisional_class_tiers'] = {
    name: confirmation_gate.leg_tier(name)
    for name in ('dom_xss', 'privilege escalation race', 'toctou', 'rate_limit')}

state = engagement.EngagementState('review.invalid')
ep = state._ep('GET', '/items/{id}')
ep.reachable_roles = ['user', 'admin']
ep.object_scoped = True
tracker = coverage_tracker.CoverageTracker()
tracker.build(coverage_tracker.endpoint_view(state), ['user', 'admin'])
results['coverage_without_any_execution'] = {
    'cells_marked_as_ran': tracker.mark_leg_attempts({'GET /items/{id}'}, ['user', 'admin']),
    'examples': [dict(identity=k[0], check=k[2], **v.to_dict())
                 for k, v in tracker.matrix.cells().items()
                 if v.status.value == 'not_detected'][:4]}

ep.add_finding({'vulnerability_class': 'idor', 'confirmed': True, 'confidence': .9,
                'severity': 'high', 'evidence': 'proof-123', 'identity_id': 'alice',
                'validator': 'cross_identity', 'summary': 'proof summary'})
ep.add_finding({'vulnerability_class': 'idor', 'confirmed': False, 'confidence': .99,
                'severity': 'high'})
results['graph_finding_after_unconfirmed_update'] = ep.findings

candidate = identity_compare.Probe(200, '{"owner":"alice","secret":"private account data"}')
anon = identity_compare.Probe(403, 'access denied')
ev = identity_compare.evaluate('authorization_boundary_compare', False,
                               candidate, candidate, candidate, anon)
results['same_identity_response_comparison'] = {
    'verdict': ev.verdict.value, 'confirmed': ev.confirmed}

gate = SafetyGate(SafetyGateConfig(active_enabled=False))
results['active_disabled_get_allowed'] = gate.authorize(
    validator_name='review', method='GET', url='https://review.invalid/').allowed
gate = SafetyGate(SafetyGateConfig(active_enabled=True, allow_mutating_replay=True,
                                  max_mutating_requests_per_finding=1))
results['mutating_ceiling_one_three_requests'] = [gate.authorize(
    validator_name='same-finding', method='POST', url='https://review.invalid/').allowed
    for _ in range(3)]

# Load the pure second-order module without importing validators or network clients.
import second_order
async def stored_echo():
    value = ''
    async def plant(v):
        nonlocal value
        value = v
    async def trigger():
        # Safe storage followed by literal display, with no SQL evaluation.
        return value
    return await second_order.confirm_second_order_sqli(plant=plant, trigger=trigger)
so = asyncio.run(stored_echo())
results['safe_stored_echo_second_order'] = {'confirmed': so.confirmed, 'reason': so.reason}

files = sorted((ROOT / 'harness').rglob('*.py'))
inventory = []
for p in files:
    text = p.read_text(encoding='utf-8-sig')
    tree = ast.parse(text)
    inventory.append({'path': str(p.relative_to(ROOT)), 'lines': len(text.splitlines()),
                      'functions': sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)),
                      'classes': sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree)),
                      'broad_handlers': sum(isinstance(n, ast.ExceptHandler) and
                                            (n.type is None or isinstance(n.type, ast.Name) and n.type.id == 'Exception')
                                            for n in ast.walk(tree))})
results['inventory'] = {'python_files': len(inventory), 'lines': sum(f['lines'] for f in inventory),
                        'largest': sorted(inventory, key=lambda f: f['lines'], reverse=True)[:12]}
(Path(__file__).parent / 'source_inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
print(json.dumps(results, indent=2))

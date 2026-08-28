package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.harness.llm.logic.IdentityCompareLogic;
import com.harness.llm.logic.SsrfCallbackLogic;
import com.harness.llm.logic.UrlIdentifierDiff;
import com.harness.llm.logic.WorkflowReplayLogic;
import com.harness.llm.logic.XssPayloadLogic;
import com.harness.llm.model.AnalysisModels.TestPlan;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

/**
 * Typed, policy-aware Burp execution plane. Each capability has its own
 * narrowly-scoped executor; there is deliberately no generic "mutate this
 * request" path controlled by model output.
 */
public final class ValidationExecutor {
    private static final int MAX_BURST = 5;
    private final MontoyaApi api;
    private final HarnessClient client;
    private final Map<String, HttpRequestResponse> sources = new ConcurrentHashMap<>();
    private final Map<String, HttpRequestResponse> exchangePool = new ConcurrentHashMap<>();

    public ValidationExecutor(MontoyaApi api, HarnessClient client) {
        this.api = api;
        this.client = client;
    }

    public void registerExchange(HttpRequestResponse rr) {
        if (rr == null) return;
        try { exchangePool.put(exchangeFingerprint(rr), rr); } catch (Exception ignored) {}
    }

    public void registerSources(HttpRequestResponse rr, Iterable<TestPlan> plans) {
        registerExchange(rr);
        for (TestPlan plan : plans) if (plan != null && plan.id != null) sources.put(plan.id, rr);
    }

    public void execute(TestPlan plan, BiConsumer<String, String> onComplete) {
        if (plan == null || plan.id == null) { onComplete.accept("ERROR", "No test plan supplied."); return; }
        HttpRequestResponse source = sources.get(plan.id);
        if (source == null) { onComplete.accept("ERROR", "Captured exchange is no longer available."); return; }
        if (!"burp".equalsIgnoreCase(plan.execution_plane)) { onComplete.accept("ERROR", "Plan is not assigned to Burp."); return; }
        if (!source.request().isInScope()) { submit(plan, source, "rejected", 0, false, "Request is outside Burp's configured scope.", ""); onComplete.accept("REJECTED", "Out-of-scope request refused."); return; }
        if (!exchangeFingerprint(source).equals(plan.source_exchange_hash)) { onComplete.accept("REJECTED", "Source request fingerprint does not match the plan."); return; }

        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() {
                try {
                    switch (plan.capability) {
                        case "reflection_context_validation" -> reflection(plan, source);
                        case "bounded_rate_limit_probe" -> rateLimit(plan, source);
                        case "workflow_replay_compare" -> workflowReplay(plan, source);
                        case "authorization_boundary_compare", "cross_identity_compare" -> identityCompare(plan, source);
                        case "controlled_callback_probe" -> controlledCallbackProbe(plan, source);
                        default -> submit(plan, source, "inconclusive", 0, false, "No typed executor exists for capability '"+plan.capability+"'.", "");
                    }
                } catch (Exception e) {
                    Outcome o=new Outcome(); o.status="error"; o.detail="Validation failed: "+e.getMessage();
                    outcomes.put(plan.id, o);
                    submit(plan, source, o.status, 0, false, o.detail, "");
                }
                return null;
            }
            @Override protected void done() { Outcome o=outcomes.remove(plan.id); if(o==null)o=new Outcome(); onComplete.accept(o.status.toUpperCase(Locale.ROOT), o.detail); }
        }.execute();
    }

    /**
     * v4.11. Was a single fixed alnum canary checked for bare substring
     * presence -- proved only that text echoes, never that HTML/JS-
     * breaking characters survive unescaped (a response that safely
     * HTML-encodes everything could still report "supported, 0.86").
     * Now loops through XssPayloadLogic.PAYLOADS (weakest-signal-last),
     * per mutable parameter, stopping at the first CONFIRMED result --
     * this is the retry-with-a-new-payload loop, bounded by the payload
     * library's own size (4) times the number of mutable parameters, so
     * there's no unbounded retry risk. No LLM is in this loop at all
     * (unlike the Python-side retry_policy.py this mirrors), so there is
     * no "escalate to a stronger model" step here -- each retry is a live
     * HTTP probe, not a judgment call, which is a stronger kind of check
     * to begin with; the closest analog to "handover" is that a SUPPORTED
     * (partial signal: something echoed, breakout didn't survive) is
     * exactly the caveat-attached status an analyst should look at
     * manually, same as before.
     */
    private void reflection(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> targets = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            targets.add(p);
        }
        if (targets.isEmpty()) {
            submit(plan, source, "inconclusive", 0, false,
                    "No mutable URL/body parameter was available for reflection validation.", "");
            return;
        }

        XssPayloadLogic.Verdict best = XssPayloadLogic.Verdict.REJECTED;
        String bestDetail = "";
        HttpParameter bestParam = null;
        XssPayloadLogic.Payload bestPayload = null;

        outer:
        for (HttpParameter param : targets) {
            List<String> tried = new ArrayList<>();
            XssPayloadLogic.Payload payload;
            while ((payload = XssPayloadLogic.nextPayload(tried)) != null) {
                tried.add(payload.template());
                String canary = "LLMHARNESS_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
                String rendered = payload.render(canary);
                var rr = api.http().sendRequest(req.withParameter(HttpParameter.parameter(param.name(), rendered, param.type())));
                String body = rr.response() == null ? "" : rr.response().bodyToString();
                XssPayloadLogic.Verdict v = XssPayloadLogic.classify(payload, canary, body);
                if (v == XssPayloadLogic.Verdict.CONFIRMED) {
                    best = v; bestParam = param; bestPayload = payload;
                    bestDetail = "param=" + param.name() + " payload=" + payload.template();
                    break outer;
                }
                if (v == XssPayloadLogic.Verdict.SUPPORTED && best != XssPayloadLogic.Verdict.SUPPORTED) {
                    best = v; bestParam = param; bestPayload = payload;
                    bestDetail = "param=" + param.name() + " payload=" + payload.template();
                    // keep trying other payloads on this param, and other params -- a SUPPORTED here
                    // doesn't stop the search for a CONFIRMED elsewhere, unlike CONFIRMED itself.
                }
            }
        }

        switch (best) {
            case CONFIRMED -> statusFor(plan, source, "confirmed", 0.9, true,
                    "A breakout payload survived unescaped in the response for parameter '" + bestParam.name() + "'.",
                    bestDetail);
            case SUPPORTED -> statusFor(plan, source, "supported", 0.6, false,
                    "Content was reflected for parameter '" + bestParam.name() + "' but no breakout payload survived "
                            + "unescaped across " + XssPayloadLogic.PAYLOADS.size() + " tried -- this does not by itself "
                            + "prove executable XSS.", bestDetail);
            default -> statusFor(plan, source, "rejected", 0.72, false,
                    "No reflection was observed for any of " + XssPayloadLogic.PAYLOADS.size()
                            + " payloads across " + targets.size() + " parameter(s).", "");
        }
    }

    private void rateLimit(TestPlan plan, HttpRequestResponse source) {
        long start=System.nanoTime(); int throttled=0; List<Integer> statuses=new ArrayList<>();
        for(int i=0;i<MAX_BURST;i++) {
            var rr=api.http().sendRequest(source.request());
            int code=rr.response()==null?0:rr.response().statusCode(); statuses.add(code);
            if(code==429 || code==503) throttled++;
        }
        double sec=(System.nanoTime()-start)/1_000_000_000.0;
        if(throttled>0) statusFor(plan,source,"supported",0.82,false,"The bounded probe triggered throttling on "+throttled+"/"+MAX_BURST+" requests.","statuses="+statuses+", duration="+String.format(Locale.ROOT,"%.2fs",sec));
        else statusFor(plan,source,"inconclusive",0.55,false,"No throttling response was observed in the bounded probe.","Absence of throttling in five requests is not proof of a rate-limit vulnerability.");
    }

    /**
     * v4.1 correction. The v4 version of this method confirmed IDOR/authz
     * findings whenever two different captured identities received a
     * similar response for the *same URL* -- which cannot distinguish a
     * real authorization failure from a resource that is simply public
     * (a homepage, a public listing). See IdentityCompareLogic's class
     * doc for the full rationale; this method's job is only to gather
     * the four HTTP observations that logic needs and hand off the
     * decision to it, rather than deciding here.
     *
     * For "cross_identity_compare" (object-level IDOR), the candidate
     * must reference a *different* object identifier than the source
     * (found via UrlIdentifierDiff) and the "attempt" is identity A's
     * session replayed with that identifier swapped in. For
     * "authorization_boundary_compare" (no identifier to swap -- e.g.
     * a low-privilege user hitting an admin-only URL) the candidate
     * must share the *same* URL, and the "attempt" is simply identity
     * A's own request replayed as-is.
     */
    private void identityCompare(TestPlan plan, HttpRequestResponse source) {
        boolean isIdor = "cross_identity_compare".equals(plan.capability);

        List<HttpRequestResponse> candidates = new ArrayList<>();
        List<UrlIdentifierDiff.Diff> diffs = new ArrayList<>();
        String sourceFingerprint = exchangeFingerprint(source);
        for (HttpRequestResponse rr : exchangePool.values()) {
            if (rr == null || rr == source) continue;
            try {
                if (exchangeFingerprint(rr).equals(sourceFingerprint)) continue;
                if (isIdor) {
                    Optional<UrlIdentifierDiff.Diff> d =
                            UrlIdentifierDiff.singleDifferingIdentifier(source.request().url(), rr.request().url());
                    if (d.isPresent()) { candidates.add(rr); diffs.add(d.get()); }
                } else if (rr.request().url().equals(source.request().url())) {
                    candidates.add(rr); diffs.add(null);
                }
            } catch (Exception ignored) {}
        }

        if (candidates.isEmpty()) {
            String need = isIdor
                    ? "No second captured request referencing a different object identifier for the same endpoint shape is available. Capture the same operation for a second identity with a different object id and retry."
                    : "No second captured request for the same URL from a different identity is available. Capture the same operation as a second identity and retry.";
            statusFor(plan, source, "inconclusive", 0, false, need, "");
            return;
        }

        String[] labels = new String[candidates.size()];
        for (int i = 0; i < candidates.size(); i++) {
            HttpRequestResponse rr = candidates.get(i);
            labels[i] = rr.request().method() + " " + rr.request().url() + " [" + exchangeFingerprint(rr).substring(0, 8) + "]";
        }
        final int[] selected = {-1};
        try {
            selected[0] = JOptionPane.showOptionDialog(null,
                    "Select the captured request made as the comparison identity (identity B).\n\n" +
                            "This assertion is analyst-controlled; the harness will not invent credentials or session state.",
                    "Select comparison identity", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
        } catch (Exception e) {
            statusFor(plan, source, "inconclusive", 0, false, "No comparison identity was selected.", "");
            return;
        }
        if (selected[0] < 0) { statusFor(plan, source, "inconclusive", 0, false, "Comparison cancelled.", ""); return; }

        HttpRequestResponse candidate = candidates.get(selected[0]);
        UrlIdentifierDiff.Diff diff = diffs.get(selected[0]);

        var sourceReplay = api.http().sendRequest(source.request());
        var candidateReplay = api.http().sendRequest(candidate.request());
        if (sourceReplay.response() == null || candidateReplay.response() == null) {
            statusFor(plan, source, "inconclusive", 0, false, "One baseline request returned no response.", "");
            return;
        }

        HttpRequest attemptReq = (isIdor && diff != null) ? applyIdentifierSwap(source.request(), diff) : source.request();
        var attemptResp = api.http().sendRequest(attemptReq);
        if (attemptResp.response() == null) {
            statusFor(plan, source, "inconclusive", 0, false, "The cross-identity attempt request returned no response.", "");
            return;
        }

        HttpRequestResponse anonResp = null;
        try {
            HttpRequest anonReq = stripIdentityHeaders(attemptReq);
            anonResp = api.http().sendRequest(anonReq);
        } catch (Exception ignored) {}

        IdentityCompareLogic.Probe sourceProbe = toProbe(sourceReplay);
        IdentityCompareLogic.Probe candidateProbe = toProbe(candidateReplay);
        IdentityCompareLogic.Probe attemptProbe = toProbe(attemptResp);
        IdentityCompareLogic.Probe anonProbe = (anonResp == null || anonResp.response() == null) ? null : toProbe(anonResp);

        boolean identifierChanged = !isIdor || diff != null;
        IdentityCompareLogic.Evidence ev = IdentityCompareLogic.evaluate(
                plan.capability, identifierChanged, sourceProbe, candidateProbe, attemptProbe, anonProbe);

        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static IdentityCompareLogic.Probe toProbe(HttpRequestResponse rr) {
        int status = rr.response() == null ? 0 : rr.response().statusCode();
        String body = rr.response() == null ? "" : rr.response().bodyToString();
        return new IdentityCompareLogic.Probe(status, body);
    }

    /**
     * Swap the differing identifier (path segment or query value) into
     * {@code req}, keeping req's own headers/cookies/session -- i.e.
     * identity A's own credentials, pointed at identity B's object.
     * Verified against the Montoya API interface source
     * (HttpRequest.withPath / .withParameter) -- these are the same
     * primitives already used elsewhere in this file for the reflection
     * canary (withParameter) -- withPath is new to this method.
     */
    private static HttpRequest applyIdentifierSwap(HttpRequest req, UrlIdentifierDiff.Diff diff) {
        if (diff.isPathDiff()) {
            String path = req.path(); // path including query, per Montoya's HttpRequest#path()
            String query = "";
            int qIdx = path.indexOf('?');
            if (qIdx >= 0) { query = path.substring(qIdx); path = path.substring(0, qIdx); }
            String[] segments = path.split("/", -1);
            int seen = -1;
            for (int i = 0; i < segments.length; i++) {
                if (segments[i].isEmpty()) continue;
                seen++;
                if (seen == diff.pathSegmentIndex) { segments[i] = diff.valueB; break; }
            }
            return req.withPath(String.join("/", segments) + query);
        }
        return req.withParameter(HttpParameter.parameter(diff.queryKey, diff.valueB, HttpParameterType.URL));
    }

    /** Strip session-identifying headers to build an unauthenticated baseline probe. */
    private static HttpRequest stripIdentityHeaders(HttpRequest req) {
        return req.withRemovedHeader("Cookie").withRemovedHeader("Authorization");
    }

    /**
     * v4.9. Replaces the previous placeholder, which called baselineCompare()
     * and always returned "inconclusive" regardless of what happened --
     * see WorkflowReplayLogic's class doc for the full rationale and scope
     * disclosure. This method's job is only to gather the three HTTP
     * observations that logic needs (baseline / boundary / malformed) and
     * hand off the decision to it, matching identityCompare()'s pattern.
     *
     * Targets the first numeric business-logic-shaped parameter found
     * (price/amount/quantity/qty/discount/count/total/balance/value --
     * see WorkflowReplayLogic.isNumericBoundaryCandidateParam). Cookies
     * are skipped, same reasoning as reflection(): mutating session state
     * isn't the point here and risks breaking the request entirely.
     */
    private void workflowReplay(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        HttpParameter target = null;
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (WorkflowReplayLogic.isNumericBoundaryCandidateParam(p.name()) && isNumeric(p.value())) {
                target = p;
                break;
            }
        }
        if (target == null) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "No numeric business-logic-shaped parameter (price/amount/quantity/qty/discount/count/total/"
                            + "balance/value) with a numeric value was available on this request for "
                            + "workflow_replay_compare.", "");
            return;
        }

        String originalValue = target.value();
        String boundaryValue = boundaryViolationValue(originalValue);
        String malformedValue = "not_a_number";

        var baselineResp = api.http().sendRequest(req);
        var boundaryResp = api.http().sendRequest(
                req.withParameter(HttpParameter.parameter(target.name(), boundaryValue, target.type())));
        var malformedResp = api.http().sendRequest(
                req.withParameter(HttpParameter.parameter(target.name(), malformedValue, target.type())));

        IdentityCompareLogic.Probe baselineProbe = baselineResp.response() == null ? null : toProbe(baselineResp);
        IdentityCompareLogic.Probe boundaryProbe = boundaryResp.response() == null ? null : toProbe(boundaryResp);
        IdentityCompareLogic.Probe malformedProbe = malformedResp.response() == null ? null : toProbe(malformedResp);

        WorkflowReplayLogic.Evidence ev = WorkflowReplayLogic.evaluate(
                target.name(), originalValue, boundaryValue, baselineProbe, boundaryProbe, malformedProbe);

        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static boolean isNumeric(String s) {
        if (s == null) return false;
        try { Double.parseDouble(s.trim()); return true; } catch (Exception e) { return false; }
    }

    /**
     * Builds a value that WorkflowReplayLogic.isGenuineBoundaryViolation
     * will accept as a real boundary case: negate non-negative values
     * (scaled up so a zero/near-zero original doesn't produce -0.0, which
     * is not "< 0" in Java -- see the isGenuineBoundaryViolation test for
     * this exact edge case), or jump three orders of magnitude for values
     * that are already negative.
     */
    private static String boundaryViolationValue(String originalValue) {
        double v = Double.parseDouble(originalValue.trim());
        double boundary = (v >= 0) ? -Math.max(Math.abs(v), 1.0) * 100 : v * 1000.0;
        if (!Double.isInfinite(boundary) && boundary == Math.rint(boundary) && Math.abs(boundary) < 1e15) {
            return Long.toString((long) boundary);
        }
        return Double.toString(boundary);
    }

    /**
     * v4.9. New capability -- the v4.6 handover explicitly flagged this as
     * having zero case in the switch statement despite planner.py already
     * generating plans for it. See SsrfCallbackLogic's class doc for the
     * full design rationale (why Collaborator, why no weaker fallback).
     *
     * Requires Burp Suite Professional with a Collaborator server
     * configured; degrades to an honest "inconclusive, here's why" status
     * rather than a crash or a fabricated result when it isn't available.
     */
    private void controlledCallbackProbe(TestPlan plan, HttpRequestResponse source) {
        HttpRequest req = source.request();
        List<HttpParameter> candidates = new ArrayList<>();
        for (var p : req.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) continue;
            if (SsrfCallbackLogic.isCallbackCandidateParam(p.name())) {
                candidates.add(p);
                if (candidates.size() >= 3) break; // bounded, same spirit as MAX_BURST elsewhere in this file
            }
        }
        if (candidates.isEmpty()) {
            SsrfCallbackLogic.Evidence ev = SsrfCallbackLogic.evaluate(List.of());
            statusFor(plan, source, ev.verdict.name().toLowerCase(Locale.ROOT), ev.confidence, ev.confirmed, ev.summary, ev.detail);
            return;
        }

        CollaboratorClient client;
        List<CollaboratorPayload> payloads = new ArrayList<>();
        try {
            client = api.collaborator().createClient();
            // generatePayload() is documented to throw IllegalStateException
            // if Collaborator is disabled -- this is the real availability
            // check, not createClient() itself.
            for (int i = 0; i < candidates.size(); i++) payloads.add(client.generatePayload());
        } catch (IllegalStateException e) {
            statusFor(plan, source, "inconclusive", 0, false,
                    "Burp Collaborator is unavailable (requires Burp Suite Professional with a Collaborator server "
                            + "configured) -- controlled_callback_probe cannot run. " + e.getMessage(), "");
            return;
        } catch (Exception e) {
            statusFor(plan, source, "error", 0, false, "Could not initialize Burp Collaborator: " + e.getMessage(), "");
            return;
        }

        for (int i = 0; i < candidates.size(); i++) {
            HttpParameter p = candidates.get(i);
            String calloutUrl = "http://" + payloads.get(i) + "/";
            try {
                api.http().sendRequest(req.withParameter(HttpParameter.parameter(p.name(), calloutUrl, p.type())));
            } catch (Exception ignored) {}
        }

        // Bounded poll -- interactions can take a few seconds to register
        // server-side, so a single immediate check (the pattern used
        // elsewhere in this file, e.g. rateLimit()) would produce false
        // negatives here specifically. Polls up to ~10s total, exits as
        // soon as any candidate has a hit.
        List<SsrfCallbackLogic.CallbackAttempt> attempts = buildAttempts(candidates, payloads, client);
        for (int round = 0; round < 5 && attempts.stream().noneMatch(a -> !a.interactionTypes.isEmpty()); round++) {
            try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            attempts = buildAttempts(candidates, payloads, client);
        }

        SsrfCallbackLogic.Evidence ev = SsrfCallbackLogic.evaluate(attempts);
        String status = ev.confirmed ? "confirmed" : ev.verdict.name().toLowerCase(Locale.ROOT);
        statusFor(plan, source, status, ev.confidence, ev.confirmed, ev.summary, ev.detail);
    }

    private static List<SsrfCallbackLogic.CallbackAttempt> buildAttempts(
            List<HttpParameter> candidates, List<CollaboratorPayload> payloads, CollaboratorClient client) {
        List<SsrfCallbackLogic.CallbackAttempt> out = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            String token = payloads.get(i).toString();
            List<Interaction> hits = client.getInteractions(InteractionFilter.interactionPayloadFilter(token));
            List<String> types = hits.stream().map(h -> h.type().name()).distinct().toList();
            out.add(new SsrfCallbackLogic.CallbackAttempt(candidates.get(i).name(), token, types));
        }
        return out;
    }

    private static final class Outcome { String status="inconclusive"; String detail=""; }
    private final Map<String, Outcome> outcomes = new ConcurrentHashMap<>();
    private void statusFor(TestPlan p,HttpRequestResponse s,String st,double conf,boolean confirmed,String summary,String evidence){ Outcome o=new Outcome(); o.status=st; o.detail=summary; outcomes.put(p.id,o); submit(p,s,st,conf,confirmed,summary,evidence); }

    private void submit(TestPlan p,HttpRequestResponse source,String status,double confidence,boolean confirmed,String summary,String evidence){
        ValidationSubmission v=new ValidationSubmission(); v.plan_id=p.id; v.status=status; v.confidence=confidence; v.confirmed=confirmed;
        v.summary=summary; v.evidence=evidence; v.executor="burp:"+p.capability; v.source_exchange_hash=exchangeFingerprint(source);
        try{ client.submitValidationResult(v); }catch(HarnessClient.HarnessException e){ api.logging().logToError("Validation submission failed: "+e.getMessage()); }
    }

    public static String exchangeFingerprint(HttpRequestResponse rr){
        try{ var req=rr.request(); MessageDigest md=MessageDigest.getInstance("SHA-256"); StringBuilder m=new StringBuilder();
            m.append(req.method().toUpperCase()).append('\u001f').append(req.url()).append('\u001f');
            req.headers().stream().map(h->Map.entry(h.name().toLowerCase(Locale.ROOT),h.value())).sorted(Map.Entry.comparingByKey()).forEach(h->m.append(h.getKey()).append(':').append(h.getValue()).append('\u001f'));
            m.append(req.bodyToString()); return HexFormat.of().formatHex(md.digest(m.toString().getBytes(StandardCharsets.UTF_8)));
        }catch(Exception e){return "";}
    }
}

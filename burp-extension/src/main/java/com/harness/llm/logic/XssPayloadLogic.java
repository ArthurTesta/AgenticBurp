package com.harness.llm.logic;

import java.util.List;

/**
 * Payload selection + verdict logic for reflection_context_validation
 * (XSS). Montoya-free for the same reason as the other *Logic classes.
 *
 * Replaces the old single-payload check (plain alnum canary, checked for
 * bare substring presence) which only ever proved text echo, never that
 * HTML/JS-breaking characters survive unescaped -- so it could report
 * "supported, 0.86 confidence" for a response that safely HTML-encodes
 * everything. PAYLOADS below are ordered weakest-signal-last: real
 * breakout attempts first, the plain canary (echo-only, proves nothing
 * about escaping) as the final fallback so it still gives a same result
 * as before when nothing sharper works.
 */
public final class XssPayloadLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Payload(String template, String rawMarker) {
        /** Substitutes the canary into this payload's template. */
        public String render(String canary) { return template.replace("__C__", canary); }
    }

    public static final List<Payload> PAYLOADS = List.of(
            new Payload("\"><script>__C__</script>", "<script>"),   // tag breakout
            new Payload("'-__C__-'", "-'"),                         // JS string breakout: "-'" surviving raw is the distinguishing signal
            new Payload("\"onmouseover=\"__C__", "onmouseover="),   // event-handler injection, no new tag
            new Payload("__C__", "")                                 // plain echo probe -- proves nothing about escaping, kept last
    );

    private XssPayloadLogic() {}

    public static Payload nextPayload(List<String> triedTemplates) {
        for (Payload p : PAYLOADS) if (!triedTemplates.contains(p.template())) return p;
        return null;
    }

    /**
     * CONFIRMED requires a genuine breakout marker (dangerous syntax, not
     * just the canary text) to survive raw in the body -- payloads with an
     * empty rawMarker (the plain echo probe) can never reach CONFIRMED,
     * only SUPPORTED, since reflecting plain text proves nothing about
     * escaping. This is the fix for the bug the plain-echo payload's own
     * test case caught: treating "the canary came back" as equally strong
     * evidence as "a script tag survived unescaped" would be wrong.
     */
    public static Verdict classify(Payload payload, String canary, String body) {
        if (body == null) return Verdict.REJECTED;
        if (!payload.rawMarker().isEmpty() && body.contains(payload.rawMarker())) {
            return Verdict.CONFIRMED;
        }
        if (body.contains(canary)) return Verdict.SUPPORTED;
        return Verdict.REJECTED;
    }
}

package com.harness.llm.logic;

import java.util.List;
import java.util.Map;

/**
 * Decision logic for identityCompare()'s candidate-selection picker:
 * given a set of candidate exchange fingerprints and the sessions known
 * for the current host, produce a display label for each candidate.
 *
 * Deliberately Montoya-free (see IdentityCompareLogic's docstring for
 * why this project keeps decision logic separate from Montoya-dependent
 * I/O) -- this class takes plain fingerprints/strings in, plain strings
 * out, so it can be unit-tested in an environment with no Montoya jar
 * and no live harness server, same as everywhere else in this package.
 *
 * Why this exists: before this, identityCompare()'s picker showed every
 * candidate as a bare "METHOD URL [fingerprint-prefix]" label with no
 * indication of which analyst-registered identity (if any) it belonged
 * to -- functionally identical to picking a raw list index. This makes
 * the picker actually informative when sessions have been registered
 * (via HarnessClient.createSession(), wired from HarnessContextMenu),
 * while degrading gracefully to the exact prior label when a candidate
 * has no registered session -- this class never requires sessions to
 * exist, it only uses them when they do.
 */
public final class IdentityLabelResolver {

    private IdentityLabelResolver() {}

    /**
     * @param method              the candidate exchange's HTTP method (e.g. "GET")
     * @param url                 the candidate exchange's URL
     * @param fingerprintPrefix   the short fingerprint prefix already used in the
     *                            existing unlabeled format (kept for continuity --
     *                            an analyst who has learned to recognize a specific
     *                            fingerprint from prior sessions shouldn't lose that)
     * @param exchangeFingerprint the candidate's FULL fingerprint, used to look up
     *                            a matching session -- not the truncated prefix,
     *                            since sessions are keyed on the full value
     * @param sessionsForHost     every session known for the current host, as
     *                            (exchange_hash -> "identity_name (identity_role)")
     *                            pairs already resolved by the caller. Resolving the
     *                            display text here (rather than passing raw identity
     *                            objects into this class) keeps this class's input
     *                            shape simple and keeps HarnessClient's response
     *                            model out of the logic package's dependencies.
     * @return the label to show in the picker for this one candidate
     */
    public static String labelFor(String method, String url, String fingerprintPrefix,
                                   String exchangeFingerprint, Map<String, String> sessionsForHost) {
        String base = method + " " + url + " [" + fingerprintPrefix + "]";
        if (sessionsForHost == null || sessionsForHost.isEmpty()) {
            return base;
        }
        String identityLabel = sessionsForHost.get(exchangeFingerprint);
        if (identityLabel == null || identityLabel.isBlank()) {
            return base;
        }
        return identityLabel + " -- " + base;
    }

    /**
     * Builds the exchange_hash -> "name (role)" lookup this class's
     * `sessionsForHost` parameter expects, from the raw
     * (exchangeHash, identityName, identityRole) triples a caller has
     * available (e.g. from HarnessClient.SessionInfo). Separated from
     * labelFor() so the two responsibilities -- "build the lookup once"
     * and "label one candidate" -- can each be tested in isolation, and
     * so labelFor() itself doesn't need to know anything about how
     * sessions are represented on the wire.
     *
     * If a host has more than one session for the same exchange_hash
     * (e.g. re-registered under two different identities by mistake),
     * the LAST one wins -- deliberately not the first, so a corrective
     * re-registration (the common real-world case: "oops, wrong
     * identity, let me fix that") actually takes effect rather than
     * silently being shadowed by the original mistake.
     */
    public static Map<String, String> buildLookup(List<SessionEntry> sessions) {
        Map<String, String> lookup = new java.util.HashMap<>();
        if (sessions == null) return lookup;
        for (SessionEntry s : sessions) {
            if (s == null || s.exchangeHash == null || s.exchangeHash.isBlank()) continue;
            String name = (s.identityName == null || s.identityName.isBlank()) ? "(unnamed identity)" : s.identityName;
            String role = (s.identityRole == null || s.identityRole.isBlank()) ? "" : " (" + s.identityRole + ")";
            lookup.put(s.exchangeHash, name + role);
        }
        return lookup;
    }

    /** Plain data carrier mirroring the fields of HarnessClient's SessionInfo that this class needs. */
    public static final class SessionEntry {
        public final String exchangeHash;
        public final String identityName;
        public final String identityRole;

        public SessionEntry(String exchangeHash, String identityName, String identityRole) {
            this.exchangeHash = exchangeHash;
            this.identityName = identityName;
            this.identityRole = identityRole;
        }
    }
}

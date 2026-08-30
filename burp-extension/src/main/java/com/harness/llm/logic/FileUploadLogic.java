package com.harness.llm.logic;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classification + payload-construction logic for
 * file_upload_validation. Montoya-free.
 *
 * Deliberately uses the EICAR antivirus test string, not any of the
 * agent's own suggested_test payloads (`<?php system($_GET['cmd']);
 * ?>` etc. -- see agents/file_upload_agent.py). EICAR
 * ("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
 * is an industry-standard, universally-recognized test signature: every
 * real antivirus/malware scanner is calibrated to flag it, but the
 * string itself is inert plain ASCII text -- not executable code in any
 * language, not real malware. That makes it the one file-upload payload
 * genuinely safe to send to a REAL, live target: if the target scans
 * uploads for known-malicious content at all, EICAR is what any real AV
 * product would catch; if it isn't scanned, the file is simply inert
 * text sitting on the server, not a working webshell. This deliberately
 * narrows the technique to what the EICAR signature can actually prove
 * -- missing malware scanning and direct uploaded-file accessibility --
 * not remote code execution, which stays analyst-confirmed only (see
 * HANDOVER.md for why that was deferred out of this pass specifically).
 *
 * The multipart body surgery here is hand-rolled rather than delegated
 * to a Montoya multipart builder because the dev-tools stub (matching
 * the real Montoya API's HttpParameterType enum) has no file-part type
 * -- only MULTIPART_ATTRIBUTE, a plain text field. multipart/form-data
 * itself is a public, documented wire format (RFC 7578), not an opaque
 * Burp-specific behavior, so constructing/parsing it directly is fully
 * verifiable without live Burp access -- unlike nosql_validation's
 * HttpParameter JSON-value ambiguity, deliberately deferred instead.
 */
public final class FileUploadLogic {

    public static final String EICAR_STRING =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private FileUploadLogic() {}

    private static final Pattern BOUNDARY_PATTERN =
            Pattern.compile("boundary=\"?([^\";\\s]+)\"?", Pattern.CASE_INSENSITIVE);

    /** @return the boundary token from a multipart/form-data Content-Type header value, or null if absent. */
    public static String extractBoundary(String contentTypeHeaderValue) {
        if (contentTypeHeaderValue == null) return null;
        Matcher m = BOUNDARY_PATTERN.matcher(contentTypeHeaderValue);
        return m.find() ? m.group(1) : null;
    }

    private static final Pattern FILENAME_PATTERN =
            Pattern.compile("filename\\s*=\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);

    /**
     * Replaces the CONTENT of the first file part (a part whose
     * Content-Disposition carries a filename=) in a multipart/form-data
     * body with newContent, preserving that part's own headers
     * (field name, filename, Content-Type) and every other part
     * untouched. Returns null if the body isn't multipart-shaped for
     * the given boundary, or no file part is found.
     */
    public static String replaceFileContent(String originalBody, String boundary, String newContent) {
        if (originalBody == null || boundary == null) return null;
        String delimiter = "--" + boundary;
        String[] parts = originalBody.split(Pattern.quote(delimiter), -1);
        if (parts.length < 2) return null;

        StringBuilder rebuilt = new StringBuilder();
        boolean foundFilePart = false;
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            boolean isTerminal = part.trim().equals("--") || (i == parts.length - 1 && part.trim().startsWith("--"));
            if (!foundFilePart && !isTerminal && FILENAME_PATTERN.matcher(part).find()) {
                String replaced = replacePartContent(part, newContent);
                if (replaced != null) {
                    part = replaced;
                    foundFilePart = true;
                }
            }
            rebuilt.append(delimiter).append(part);
            if (i == 0) {
                // The split() call already consumed the leading delimiter for
                // part[0] being empty (body starts with "--boundary"), so the
                // first real part needs no extra delimiter prefix beyond what
                // the loop already appends uniformly -- handled by starting
                // rebuilt fresh per iteration rather than skipping index 0.
            }
        }
        if (!foundFilePart) return null;
        // The split-and-rejoin above re-inserts a delimiter before EVERY
        // element including the empty string before the body's own leading
        // delimiter, producing one extra leading delimiter -- strip it.
        String result = rebuilt.toString();
        return result.startsWith(delimiter + delimiter) ? result.substring(delimiter.length()) : result;
    }

    /** Within one multipart part's raw text (headers + blank line + content), replace just the content. */
    private static String replacePartContent(String part, String newContent) {
        int headerEnd = part.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (headerEnd < 0) {
            headerEnd = part.indexOf("\n\n");
            sepLen = 2;
        }
        if (headerEnd < 0) return null;
        String headers = part.substring(0, headerEnd);
        String lineEnding = sepLen == 4 ? "\r\n" : "\n";
        return headers + lineEnding + lineEnding + newContent + lineEnding;
    }

    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s\"'<>]+|/[\\w./-]*\\.[A-Za-z0-9]{1,8}\\b");

    /** Best-effort extraction of a URL/path pointing at the uploaded file from the upload response body. */
    public static String extractUrl(String uploadResponseBody) {
        if (uploadResponseBody == null) return null;
        Matcher m = URL_PATTERN.matcher(uploadResponseBody);
        return m.find() ? m.group(0) : null;
    }

    /**
     * @param uploadStatusCode status of the upload request itself
     * @param extractedUrl a URL/path the executor found in the upload response pointing at the file, or null
     * @param fetchStatusCode status of fetching that URL back (only meaningful if extractedUrl != null)
     * @param fetchedBodyContainsEicar whether the fetched content contains the EICAR string verbatim
     */
    public static Evidence evaluate(int uploadStatusCode, String extractedUrl, int fetchStatusCode, boolean fetchedBodyContainsEicar) {
        boolean uploadAccepted = uploadStatusCode >= 200 && uploadStatusCode < 300;
        if (!uploadAccepted) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "Upload of a file containing the EICAR antivirus test signature was rejected (status "
                            + uploadStatusCode + ") -- no evidence of a file-upload vulnerability here.", "");
        }
        if (extractedUrl == null) {
            return new Evidence(Verdict.SUPPORTED, 0.4, false,
                    "The EICAR test file was accepted (status " + uploadStatusCode + ") but no accessible "
                            + "URL/path was found in the response to confirm whether the file is retrievable "
                            + "and unscanned.", "");
        }
        if (fetchStatusCode >= 200 && fetchStatusCode < 300 && fetchedBodyContainsEicar) {
            return new Evidence(Verdict.CONFIRMED, 0.85, true,
                    "A file containing the industry-standard EICAR antivirus test signature was accepted, "
                            + "stored, and is retrievable verbatim at a URL/path the server itself returned -- "
                            + "confirms the upload was not scanned for known-malicious content and that uploaded "
                            + "files are directly web-accessible. EICAR is inert (plain text, not executable in "
                            + "any language), so this test carried no risk to the target.",
                    "url=" + extractedUrl);
        }
        return new Evidence(Verdict.SUPPORTED, 0.5, false,
                "The EICAR test file was accepted and a URL/path was returned, but fetching it back "
                        + "(status " + fetchStatusCode + ") did not confirm the file is retrievable and "
                        + "unmodified.", "url=" + extractedUrl);
    }
}

package com.harness.llm.logic;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive scan for deserialization_format_confirmation. Montoya-free, no
 * new request needed -- classifies the request body Burp already
 * captured.
 *
 * Deliberately ASCII-text-only signatures (base64 text, PHP's serialize()
 * text format, a distinctive field name), never raw binary magic bytes
 * (e.g. Java serialization's 0xAC 0xED header, .NET BinaryFormatter's
 * leading bytes). The reason is a real, unresolved question this
 * project can't answer from this sandbox: HttpMessage.bodyToString()'s
 * exact byte-to-String decoding is not documented anywhere findable, and
 * a raw non-ASCII byte sequence run through an unknown decoder could
 * come out as anything (mangled multi-byte sequences, replacement
 * characters) depending on what that decoding actually is. Every
 * signature below is confirmed to survive ANY common single- or
 * multi-byte text encoding unchanged, because it's pure ASCII --
 * sidestepping the question instead of guessing at its answer.
 *
 * This confirms the FORMAT is present, not that it's exploitable --
 * exploitability of a deserialization sink depends on what
 * classes/gadget chains are reachable, which this can't determine.
 */
public final class DeserializationFormatLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private record NamedPattern(String label, Pattern pattern, Verdict tier) {}

    private static final List<NamedPattern> PATTERNS = List.of(
            // Base64-encoded Java serialized object always starts with
            // "rO0AB" -- the base64 encoding of the fixed magic bytes
            // 0xAC 0xED 0x00 0x05 that every java.io.ObjectOutputStream
            // stream begins with. This is about as specific a signature
            // as exists in this space.
            new NamedPattern("Java serialized object (base64)", Pattern.compile("\\brO0AB[A-Za-z0-9+/=]{3,}"), Verdict.CONFIRMED),
            // PHP's serialize() format: a:N:{ (array), O:N:"Class": (object),
            // s:N:"value" (string), i:N; (int) -- the type-letter + length
            // + colon shape is distinctive enough to not appear in
            // ordinary text by coincidence.
            new NamedPattern("PHP serialized data", Pattern.compile("\\b[aOs]:\\d+:\"?"), Verdict.CONFIRMED),
            // ASP.NET ViewState -- presence indicates the technology is in
            // use, not by itself an exploitable finding (ViewState is
            // often MAC-protected), hence SUPPORTED not CONFIRMED.
            new NamedPattern("ASP.NET ViewState field", Pattern.compile("__VIEWSTATE"), Verdict.SUPPORTED)
    );

    private DeserializationFormatLogic() {}

    public static Evidence evaluate(String requestBody) {
        if (requestBody == null || requestBody.isEmpty()) {
            return new Evidence(Verdict.REJECTED, 0.7, false, "Request body is empty -- nothing to scan.", "");
        }

        Map<String, String> confirmedMatches = new LinkedHashMap<>();
        Map<String, String> supportedMatches = new LinkedHashMap<>();
        for (NamedPattern np : PATTERNS) {
            Matcher m = np.pattern().matcher(requestBody);
            if (m.find()) {
                String snippet = requestBody.substring(m.start(), Math.min(requestBody.length(), m.end() + 20));
                if (np.tier() == Verdict.CONFIRMED) confirmedMatches.put(np.label(), snippet);
                else supportedMatches.put(np.label(), snippet);
            }
        }

        if (!confirmedMatches.isEmpty()) {
            String labels = String.join(", ", confirmedMatches.keySet());
            return new Evidence(Verdict.CONFIRMED, 0.85, true,
                    "Request body contains a recognizable serialized-data signature: " + labels
                            + ". This confirms the format is present and likely reaches a deserializer -- "
                            + "not that it is exploitable, which depends on what gadget chain the "
                            + "deserializer's classpath can reach.",
                    confirmedMatches.toString());
        }
        if (!supportedMatches.isEmpty()) {
            String labels = String.join(", ", supportedMatches.keySet());
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "Request body references a serialization-related technology (" + labels
                            + ") without a directly confirmable payload signature -- worth checking whether "
                            + "it's cryptographically protected (e.g. ViewState MAC) before assuming it's reachable.",
                    supportedMatches.toString());
        }
        return new Evidence(Verdict.REJECTED, 0.72, false,
                "No recognized serialized-data format signature found in the request body.", "");
    }
}

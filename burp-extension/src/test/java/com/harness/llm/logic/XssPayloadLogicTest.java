package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.harness.llm.logic.XssPayloadLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class XssPayloadLogicTest {

    @Test
    @DisplayName("nextPayload cycles through untried payloads, ends at null")
    void nextPayloadCyclesAndExhausts() {
        List<String> tried = new ArrayList<>();
        int count = 0;
        Payload p;
        while ((p = nextPayload(tried)) != null) {
            assertFalse(tried.contains(p.template()));
            tried.add(p.template());
            count++;
            if (count > 10) fail("nextPayload did not terminate");
        }
        assertEquals(PAYLOADS.size(), count);
    }

    @Test
    @DisplayName("raw tag breakout surviving unescaped -> CONFIRMED")
    void rawBreakoutIsConfirmed() {
        Payload p = PAYLOADS.get(0); // "><script>__C__</script>
        String canary = "ABC123";
        Verdict v = classify(p, canary, "<html>\"><script>ABC123</script></html>");
        assertEquals(Verdict.CONFIRMED, v);
    }

    @Test
    @DisplayName("HTML-encoded reflection is not confirmed, only the plain canary text counts as echo")
    void encodedReflectionIsNotConfirmed() {
        Payload p = PAYLOADS.get(0);
        String canary = "ABC123";
        String encoded = "&quot;&gt;&lt;script&gt;ABC123&lt;/script&gt;";
        Verdict v = classify(p, canary, encoded);
        assertEquals(Verdict.SUPPORTED, v, "canary text itself is present (as encoded-neighbor text), breakout chars are not");
    }

    @Test
    @DisplayName("nothing reflected at all -> REJECTED")
    void nothingReflectedIsRejected() {
        Payload p = PAYLOADS.get(0);
        Verdict v = classify(p, "ABC123", "<html>no match here</html>");
        assertEquals(Verdict.REJECTED, v);
    }

    @Test
    @DisplayName("null body does not throw, classified REJECTED")
    void nullBodyIsSafe() {
        assertEquals(Verdict.REJECTED, classify(PAYLOADS.get(0), "ABC123", null));
    }

    @Test
    @DisplayName("plain-echo payload (last resort) can never reach CONFIRMED, only SUPPORTED")
    void plainCanaryPayloadCapsAtSupported() {
        Payload plain = PAYLOADS.get(PAYLOADS.size() - 1);
        assertEquals("", plain.rawMarker());
        Verdict v = classify(plain, "ABC123", "<div>ABC123</div>");
        assertEquals(Verdict.SUPPORTED, v, "reflecting plain text proves nothing about escaping -- must not confirm");
    }

    @Test
    @DisplayName("JS string breakout surviving raw -> CONFIRMED")
    void jsBreakoutIsConfirmed() {
        Payload p = PAYLOADS.get(1); // '-__C__-'
        Verdict v = classify(p, "ABC123", "<script>var x='-ABC123-'</script>");
        assertEquals(Verdict.CONFIRMED, v);
    }
}

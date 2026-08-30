package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.InfoDisclosureLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class InfoDisclosureLogicTest {

    @Test
    @DisplayName("empty body -> rejected")
    void emptyBodyIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate("").verdict());
        assertEquals(Verdict.REJECTED, evaluate(null).verdict());
    }

    @Test
    @DisplayName("clean JSON response -> rejected")
    void cleanResponseIsRejected() {
        Evidence e = evaluate("{\"status\": \"ok\", \"data\": []}");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("real Java stack trace -> confirmed")
    void javaStackTraceIsConfirmed() {
        String body = "Internal Server Error\n\tat com.example.Foo.bar(Foo.java:42)\n\tat com.example.Baz.qux(Baz.java:17)";
        Evidence e = evaluate(body);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("Python traceback -> confirmed")
    void pythonTracebackIsConfirmed() {
        String body = "Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>\nZeroDivisionError: division by zero";
        assertEquals(Verdict.CONFIRMED, evaluate(body).verdict());
    }

    @Test
    @DisplayName("Spring Boot Whitelabel error page -> confirmed")
    void whitelabelErrorPageIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("<h1>Whitelabel Error Page</h1><p>This application has no explicit mapping</p>").verdict());
    }

    @Test
    @DisplayName("SQL error message -> confirmed")
    void sqlErrorIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("You have an error in your SQL syntax; check the manual").verdict());
    }

    @Test
    @DisplayName("bare absolute path with no error context -> rejected (too weak/common alone)")
    void barePathAloneIsRejected() {
        Evidence e = evaluate("Check out our blog post at /home/articles/my-post for more info.");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("absolute path near error-shaped words -> supported, not confirmed")
    void pathNearErrorContextIsSupported() {
        Evidence e = evaluate("Error: failed to open file: /var/www/html/config/secrets.php");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}

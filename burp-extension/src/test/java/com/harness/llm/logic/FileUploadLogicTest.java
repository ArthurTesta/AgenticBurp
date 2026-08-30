package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.FileUploadLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class FileUploadLogicTest {

    @Test
    @DisplayName("EICAR string decodes to the real, correct-length signature with no executable code")
    void eicarStringIsCorrect() {
        // Deliberately NOT asserting against the literal signature text
        // here -- see FileUploadLogic's own comment on why it's
        // Base64-encoded in that file; embedding the raw string in this
        // test file would reintroduce the exact problem that fix exists
        // to avoid (a real antivirus product correctly treats the literal
        // signature as a detection hit wherever it appears on disk).
        assertEquals(68, EICAR_STRING.length());
        assertTrue(EICAR_STRING.startsWith("X5O!P%@AP"));
        assertTrue(EICAR_STRING.endsWith("H+H*"));
        assertFalse(EICAR_STRING.contains("<?php"));
        assertFalse(EICAR_STRING.contains("<script"));
    }

    @Test
    @DisplayName("extractBoundary parses a quoted or unquoted boundary from a Content-Type header value")
    void extractBoundaryParsesBothForms() {
        assertEquals("----WebKitFormBoundaryABC123",
                extractBoundary("multipart/form-data; boundary=----WebKitFormBoundaryABC123"));
        assertEquals("myBoundary",
                extractBoundary("multipart/form-data; boundary=\"myBoundary\""));
        assertNull(extractBoundary("application/json"));
        assertNull(extractBoundary(null));
    }

    @Test
    @DisplayName("replaceFileContent preserves the file part's headers, replaces only the content")
    void replaceFileContentPreservesHeaders() {
        String boundary = "BOUNDARY";
        String body = "--BOUNDARY\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
                + "Content-Type: text/plain\r\n"
                + "\r\n"
                + "original content\r\n"
                + "--BOUNDARY--\r\n";

        String result = replaceFileContent(body, boundary, EICAR_STRING);

        assertNotNull(result);
        assertTrue(result.contains("filename=\"test.txt\""));
        assertTrue(result.contains("Content-Type: text/plain"));
        assertTrue(result.contains(EICAR_STRING));
        assertFalse(result.contains("original content"));
    }

    @Test
    @DisplayName("replaceFileContent leaves other (non-file) parts untouched")
    void replaceFileContentLeavesOtherPartsAlone() {
        String boundary = "BOUNDARY";
        String body = "--BOUNDARY\r\n"
                + "Content-Disposition: form-data; name=\"description\"\r\n"
                + "\r\n"
                + "a comment field\r\n"
                + "--BOUNDARY\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
                + "Content-Type: text/plain\r\n"
                + "\r\n"
                + "original content\r\n"
                + "--BOUNDARY--\r\n";

        String result = replaceFileContent(body, boundary, EICAR_STRING);

        assertNotNull(result);
        assertTrue(result.contains("a comment field"));
        assertTrue(result.contains(EICAR_STRING));
        assertFalse(result.contains("original content"));
    }

    @Test
    @DisplayName("replaceFileContent returns null when no filename= part exists (nothing to target)")
    void replaceFileContentReturnsNullWithNoFilePart() {
        String boundary = "BOUNDARY";
        String body = "--BOUNDARY\r\n"
                + "Content-Disposition: form-data; name=\"description\"\r\n"
                + "\r\n"
                + "just a text field\r\n"
                + "--BOUNDARY--\r\n";
        assertNull(replaceFileContent(body, boundary, EICAR_STRING));
    }

    @Test
    @DisplayName("extractUrl finds an absolute URL in a JSON-ish upload response")
    void extractUrlFindsAbsoluteUrl() {
        String body = "{\"status\":\"ok\",\"url\":\"http://target.test/uploads/test.txt\"}";
        assertEquals("http://target.test/uploads/test.txt", extractUrl(body));
    }

    @Test
    @DisplayName("extractUrl finds a relative path when no absolute URL is present")
    void extractUrlFindsRelativePath() {
        String body = "{\"status\":\"ok\",\"path\":\"/uploads/eicar_test.txt\"}";
        assertEquals("/uploads/eicar_test.txt", extractUrl(body));
    }

    @Test
    @DisplayName("extractUrl returns null when nothing URL-shaped is present")
    void extractUrlReturnsNullWhenAbsent() {
        assertNull(extractUrl("{\"status\":\"ok\"}"));
        assertNull(extractUrl(null));
    }

    @Test
    @DisplayName("upload rejected (non-2xx) -> rejected, no risk taken")
    void uploadRejectedIsRejected() {
        Evidence e = evaluate(400, null, -1, false);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("upload accepted but no URL found -> supported only")
    void uploadAcceptedNoUrlIsSupported() {
        Evidence e = evaluate(200, null, -1, false);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("upload accepted, URL found, fetched back with EICAR content intact -> confirmed")
    void uploadAcceptedAndFetchedBackConfirmsFinding() {
        Evidence e = evaluate(201, "/uploads/eicar_test.txt", 200, true);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("upload accepted, URL found, but fetch doesn't confirm EICAR content -> supported only")
    void uploadAcceptedUrlFoundButFetchInconclusiveIsSupported() {
        Evidence e = evaluate(200, "/uploads/eicar_test.txt", 404, false);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}

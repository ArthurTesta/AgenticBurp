package org.junit.jupiter.api;
// Stub covering exactly the overloads used in this project's test files,
// verified against the real signatures in junit-team/junit5's
// Assertions.java (assertTrue/assertFalse/assertEquals/assertNull with
// boolean/Object + String message overloads).
public class Assertions {
    public static void assertTrue(boolean condition) { assertTrue(condition, (String) null); }
    public static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message == null ? "expected true" : message);
    }
    public static void assertFalse(boolean condition) { assertFalse(condition, (String) null); }
    public static void assertFalse(boolean condition, String message) {
        if (condition) throw new AssertionError(message == null ? "expected false" : message);
    }
    public static void assertEquals(Object expected, Object actual) { assertEquals(expected, actual, (String) null); }
    public static void assertEquals(Object expected, Object actual, String message) {
        boolean eq = (expected == null) ? (actual == null) : expected.equals(actual);
        if (!eq) throw new AssertionError((message == null ? "" : message + " -- ") + "expected <" + expected + "> but was <" + actual + ">");
    }
    public static void assertNull(Object actual) {
        if (actual != null) throw new AssertionError("expected null but was <" + actual + ">");
    }
    public static void assertNotNull(Object actual) {
        if (actual == null) throw new AssertionError("expected non-null");
    }
    public static <V> V fail(String message) { throw new AssertionError(message); }
}

package com.harness.llm.logic;

import java.util.List;

/**
 * Classification for race_condition_validation. Montoya-free.
 *
 * The technique: fire a genuinely CONCURRENT burst of identical replays
 * of a captured mutating request (e.g. a single-use coupon redemption,
 * a limited-stock purchase) and look at how many came back with a
 * success-shaped (2xx) status. A correctly-enforced single-use/limited
 * resource should let at most one concurrent attempt succeed; MORE than
 * one succeeding is the specific signature of a check-then-act (TOCTOU)
 * race window letting multiple requests pass the check before any of
 * them commits its write. This is the same underlying bug class
 * testing/test-target/'s own PixelMart coupon-redemption endpoint was
 * built to demonstrate by hand (see its own docstring:
 * "non-atomic check-then-write (TOCTOU)").
 *
 * Deliberately NOT single-request-vs-baseline: firing the burst
 * genuinely concurrently (not sequentially) is what actually opens the
 * race window at all -- see ValidationExecutor.raceConditionBurst,
 * which uses a real thread pool for exactly this reason, unlike every
 * other executor method in that file (which replay sequentially,
 * appropriately, since none of them need simultaneity to work).
 */
public final class RaceConditionLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    public record AttemptResult(int statusCode) {}

    private RaceConditionLogic() {}

    private static boolean isSuccess(AttemptResult a) {
        return a.statusCode() >= 200 && a.statusCode() < 300;
    }

    public static Evidence evaluate(List<AttemptResult> attempts) {
        int n = attempts.size();
        long successCount = attempts.stream().filter(RaceConditionLogic::isSuccess).count();
        List<Integer> statuses = attempts.stream().map(AttemptResult::statusCode).toList();

        if (successCount >= 2 && successCount < n) {
            return new Evidence(Verdict.CONFIRMED, 0.75, true,
                    "Firing " + n + " concurrent identical replays of this request produced " + successCount
                            + " successful (2xx) responses instead of at most one -- consistent with a "
                            + "check-then-act (TOCTOU) race condition letting a single-use or limited resource "
                            + "be consumed more than the intended number of times.",
                    "statuses=" + statuses);
        }
        if (successCount == n && n > 1) {
            return new Evidence(Verdict.SUPPORTED, 0.45, false,
                    "All " + n + " concurrent replays succeeded (2xx) -- consistent with either a race window "
                            + "wide enough that every attempt won it, or with this endpoint not enforcing any "
                            + "single-use/limit at all. This burst alone can't distinguish the two; a single "
                            + "sequential replay confirming whether the action can be repeated at all would help.",
                    "statuses=" + statuses);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "At most one of " + n + " concurrent replays succeeded (2xx) -- no evidence of a race condition; "
                        + "the limit/single-use check appears to be enforced correctly under concurrency.",
                "statuses=" + statuses);
    }
}

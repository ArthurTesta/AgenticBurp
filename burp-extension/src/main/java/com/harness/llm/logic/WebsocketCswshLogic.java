package com.harness.llm.logic;

/**
 * Classification logic for websocket_cswsh_validation (Cross-Site WebSocket
 * Hijacking). Montoya-free. The executor replays a WebSocket handshake (an
 * Upgrade: websocket request) with a foreign Origin header and hands over the
 * resulting handshake status. A server that completes the handshake (101) for an
 * arbitrary Origin, while the connection is authenticated by cookies, is
 * CSWSH-able: an attacker page can open an authenticated socket.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class WebsocketCswshLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private WebsocketCswshLogic() {}

    /**
     * @param isWebsocketUpgrade   whether the captured request was a WebSocket handshake
     * @param requestCarriesAuth   whether the handshake sent a cookie / Authorization (so the socket is authenticated)
     * @param foreignOriginStatus  handshake status when replayed with a foreign Origin (-1 if none)
     */
    public static Evidence evaluate(boolean isWebsocketUpgrade, boolean requestCarriesAuth,
                                    int foreignOriginStatus) {
        if (!isWebsocketUpgrade) {
            return new Evidence(Verdict.INVALID, 0, false,
                    "This request is not a WebSocket handshake (no Upgrade: websocket) -- "
                            + "websocket_cswsh_validation does not apply.", "");
        }
        if (foreignOriginStatus < 0) {
            return new Evidence(Verdict.REJECTED, 0.5, false,
                    "The foreign-Origin handshake replay produced no response.", "");
        }
        boolean handshakeAccepted = foreignOriginStatus == 101;
        if (handshakeAccepted && requestCarriesAuth) {
            return new Evidence(Verdict.CONFIRMED, 0.88, true,
                    "The server completed the WebSocket handshake (101) for an arbitrary foreign Origin on an "
                            + "authenticated (cookie/token-bearing) connection -- it does not enforce Origin, so an "
                            + "attacker page can open an authenticated socket on the victim's behalf (Cross-Site "
                            + "WebSocket Hijacking).",
                    "foreignOriginStatus=101 authenticated=true");
        }
        if (handshakeAccepted) {
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "The server completed the handshake (101) for a foreign Origin, but no credentials were "
                            + "observed on the handshake -- Origin is unenforced, though impact depends on whether the "
                            + "socket carries authenticated context.",
                    "foreignOriginStatus=101 authenticated=false");
        }
        return new Evidence(Verdict.REJECTED, 0.75, false,
                "The server did not complete the WebSocket handshake for a foreign Origin (status "
                        + foreignOriginStatus + ") -- Origin appears to be enforced.",
                "foreignOriginStatus=" + foreignOriginStatus);
    }
}

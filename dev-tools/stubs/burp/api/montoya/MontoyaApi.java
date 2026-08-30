package burp.api.montoya;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.collaborator.Collaborator;
// Minimal stub: only the three accessors ValidationExecutor.java calls.
// Verified against the real interface: http(), logging(), collaborator()
// all present with these exact return types.
public interface MontoyaApi {
    Http http();
    Logging logging();
    Collaborator collaborator();
}

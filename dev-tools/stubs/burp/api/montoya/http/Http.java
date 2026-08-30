package burp.api.montoya.http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
public interface Http {
    HttpRequestResponse sendRequest(HttpRequest request);
}

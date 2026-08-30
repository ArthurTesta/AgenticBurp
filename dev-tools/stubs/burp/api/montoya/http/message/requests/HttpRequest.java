package burp.api.montoya.http.message.requests;
import java.util.List;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
public interface HttpRequest {
    boolean isInScope();
    String url();
    String method();
    String path();
    List<ParsedHttpParameter> parameters();
    List<HttpHeader> headers();
    String bodyToString();
    HttpRequest withPath(String path);
    HttpRequest withParameter(HttpParameter parameter);
    HttpRequest withRemovedHeader(String name);
    HttpRequest withAddedHeader(String name, String value);
    HttpRequest withUpdatedHeader(String name, String value);
    HttpRequest withBody(String body);
}

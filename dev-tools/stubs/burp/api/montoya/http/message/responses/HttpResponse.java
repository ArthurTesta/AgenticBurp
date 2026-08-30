package burp.api.montoya.http.message.responses;
import burp.api.montoya.http.message.HttpHeader;
import java.util.List;
public interface HttpResponse {
    short statusCode();
    String bodyToString();
    List<HttpHeader> headers();
    boolean hasHeader(String name);
    HttpHeader header(String name);
    String headerValue(String name);
}

package burp.api.montoya.http.message.responses;
public interface HttpResponse {
    short statusCode();
    String bodyToString();
}

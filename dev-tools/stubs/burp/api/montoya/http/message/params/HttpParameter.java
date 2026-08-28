package burp.api.montoya.http.message.params;
public interface HttpParameter {
    HttpParameterType type();
    String name();
    String value();
    static HttpParameter parameter(String name, String value, HttpParameterType type) {
        throw new UnsupportedOperationException("stub");
    }
}

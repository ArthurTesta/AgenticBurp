package burp.api.montoya.http.message.params;
public interface ParsedHttpParameter extends HttpParameter {
    @Override HttpParameterType type();
    @Override String name();
    @Override String value();
}

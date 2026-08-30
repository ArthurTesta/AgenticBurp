package burp.api.montoya.collaborator;
public interface InteractionFilter {
    boolean matches(Object server, Interaction interaction);
    static InteractionFilter interactionPayloadFilter(String payload) {
        throw new UnsupportedOperationException("stub");
    }
}

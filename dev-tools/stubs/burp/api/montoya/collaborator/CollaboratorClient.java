package burp.api.montoya.collaborator;
import java.util.List;
public interface CollaboratorClient extends CollaboratorPayloadGenerator {
    @Override CollaboratorPayload generatePayload(PayloadOption... options);
    List<Interaction> getInteractions(InteractionFilter filter);
}

package org.keycloak.extensions.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.Arrays;
import java.util.List;

public class RegisterEventListenerProviderFactory implements EventListenerProviderFactory {

    private List<String> realms;
    private List<String> clientIds;
    private String apiBaseUrl;
    private String authBaseUrl;
    private String authRealm;
    private String authClientId;
    private String authClientSecret;
    private String learningBaseUrl;
    private String learningApiToken;
    private String lifterApiKey;
    private String lifterApiSecret;
    
    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new RegisterEventListenerProvider(
            session,
            realms,
            clientIds,
            apiBaseUrl,
            authBaseUrl,
            authRealm,
            authClientId,
            authClientSecret,
            learningBaseUrl,
            learningApiToken,
            lifterApiKey,
            lifterApiSecret
        );
    }
    
    @Override
    public void init(Config.Scope config) {

        String realmsConfig = config.get("realms");
        if (realmsConfig != null) {
            realms = Arrays.asList(realmsConfig.split(","));
        }
        
        String clientIdsConfig = config.get("clientIds");
        if (clientIdsConfig != null) {
            clientIds = Arrays.asList(clientIdsConfig.split(","));
        }
        
        apiBaseUrl = config.get("apiBaseUrl");
        authBaseUrl = config.get("authBaseUrl");
        authRealm = config.get("authRealm");
        authClientId = config.get("authClientId");
        authClientSecret = config.get("authClientSecret");
        learningBaseUrl = config.get("learningBaseUrl");
        learningApiToken = config.get("learningApiToken");
        lifterApiKey = config.get("lifterApiKey");
        lifterApiSecret = config.get("lifterApiSecret");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "register";
    }
}
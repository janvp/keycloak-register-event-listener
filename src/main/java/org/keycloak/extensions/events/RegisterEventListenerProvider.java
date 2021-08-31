package org.keycloak.extensions.events;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.util.List;

import okhttp3.*;

public class RegisterEventListenerProvider implements EventListenerProvider {

    private static Logger logger = Logger.getLogger(RegisterEventListenerProvider.class);
    private final OkHttpClient httpClient = new OkHttpClient();
    private final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private final String tempLastNameCrm = "TEMP_KEYCLOAK";
    private KeycloakSession session;
    private String apiToken;
    private List<String> realms;
    private List<String> clientIds;
    private String apiBaseUrl;
    private String authBaseUrl;
    private String authRealm;
    private String authClientId;
    private String authClientSecret;

    public RegisterEventListenerProvider(KeycloakSession session, List<String> realms, List<String> clientIds,
            String apiBaseUrl, String authBaseUrl, String authRealm, String authClientId, String authClientSecret) {
        this.session = session;
        this.realms = realms;
        this.clientIds = clientIds;
        this.apiBaseUrl = apiBaseUrl;
        this.authBaseUrl = authBaseUrl;
        this.authRealm = authRealm;
        this.authClientId = authClientId;
        this.authClientSecret = authClientSecret;
    }

    @Override
    public void onEvent(Event event) {

        // Check if the realm and client ID are in the list to handle
        if (realms != null && !realms.contains(event.getRealmId())
                || clientIds != null && !clientIds.contains(event.getClientId())) {
            logger.info("Realm and client ID not handled. Realm: " + event.getRealmId() + ", Client: " + event.getClientId());
            return;
        }

        if (event.getType() == EventType.REGISTER) {
            handleRegister(event);
        } else if (event.getType() == EventType.LOGIN) {
            handleLogin(event);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    }

    @Override
    public void close() {
    }

    private void handleLogin(Event event) {
        logger.info("Handle Login");
        UserModel user = session.users().getUserById(event.getUserId(), session.getContext().getRealm());
        try {
            setApiToken();
            JSONObject crmRecord = getCrmRecord(user.getEmail());
            if (crmRecord != null) {
                String lastNameCrm = crmRecord.getJSONObject("record").getString("Last_Name");
                if (lastNameCrm.equals(tempLastNameCrm)) {
                    logger.info("Updating CRM record with temporary name");
                    String crmId = crmRecord.getJSONObject("record").getString("id");
                    JSONObject bodyJSON = new JSONObject();
                    bodyJSON.put("First_Name", user.getFirstName());
                    bodyJSON.put("Last_Name", user.getLastName());
                    List<String> mobileNumberList = user.getAttribute("mobile_number");
                    if (!mobileNumberList.isEmpty()) {
                        bodyJSON.put("Phone", mobileNumberList.get(0));
                    }
                    updateCrmRecord(crmId, bodyJSON);
                }
            }
        } catch (IOException e) {
            logger.error("Error updating CRM during LOGIN event: " + e.toString());
            e.printStackTrace();
        }
    }

    private void handleRegister(Event event) {
        logger.info("Handle Register");
        String userId = event.getUserId();
        String email = event.getDetails().get("email");
    
        try {
            setApiToken();
            JSONObject crmRecord = getCrmRecord(email);
            if (crmRecord == null) {
                logger.info("CRM record not found. Creating new one.");
                createCrmRecord(userId, email);
            } else {
                logger.info("CRM record found. Updating.");
                String crmId = crmRecord.getJSONObject("record").getString("id");
                JSONObject bodyJSON = new JSONObject();
                bodyJSON.put("Keycloak_ID", userId);
                updateCrmRecord(crmId, bodyJSON);
            }
        } catch (IOException e) {
            logger.error("Error updating CRM during REGISTER event: " + e.toString());
            e.printStackTrace();
        }
    }

    private JSONObject getCrmRecord(String email) throws IOException {
        String url = apiBaseUrl + "/api/zoho/record/?email=" + email;
        Request request = new Request.Builder().url(url).addHeader("Authorization", "Bearer " + apiToken).build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.code() == 422) {
                return null;
            } else if (!response.isSuccessful()) {
                throw new IOException("Error while fetching record from CRM. " + response);
            }
    
            String responseBody = response.body().string();

            return new JSONObject(responseBody);
        }
    }

    private void createCrmRecord(String userId, String email) throws IOException {
        JSONObject bodyJSON = new JSONObject();
        bodyJSON.put("Email", email);
        bodyJSON.put("Last_Name", tempLastNameCrm);
        bodyJSON.put("Keycloak_ID", userId);
        bodyJSON.put("Lead_Source", "My Plibo");
        bodyJSON.put("Lead_Status", "000. New Digital hot lead");

        RequestBody body = RequestBody.create(bodyJSON.toString(), JSON);
        String url = apiBaseUrl + "/api/zoho/lead/";
        Request request = new Request.Builder().url(url).post(body).addHeader("Authorization", "Bearer " + apiToken)
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Error while creating lead in CRM. " + response);
            }
        }
    }

    private void updateCrmRecord(String crmId, JSONObject bodyJSON) throws IOException {
        RequestBody body = RequestBody.create(bodyJSON.toString(), JSON);
        String url = apiBaseUrl + "/api/zoho/record/?id=" + crmId;
        Request request = new Request.Builder().url(url).put(body).addHeader("Authorization", "Bearer " + apiToken)
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Error while updating record in CRM. " + response);
            }
        }
    }

    private void setApiToken() throws IOException {
        RequestBody body = new FormBody.Builder().add("grant_type", "client_credentials").add("client_id", authClientId)
                .add("client_secret", authClientSecret).build();
        String url = authBaseUrl + "/auth/realms/" + authRealm + "/protocol/openid-connect/token";
        Request request = new Request.Builder().url(url).post(body).build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Error while requesting API token. " + response);
            }
    
            String responseBody = response.body().string();
            JSONObject responseJSON = new JSONObject(responseBody);
            apiToken = responseJSON.getString("access_token");
        }
    }
}
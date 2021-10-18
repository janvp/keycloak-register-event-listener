package org.keycloak.extensions.events;

import java.io.IOException;
import java.util.List;
import javax.ws.rs.core.MultivaluedMap;
import okhttp3.*;
import org.apache.commons.text.RandomStringGenerator;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.json.JSONObject;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

public class RegisterEventListenerProvider implements EventListenerProvider {

    private static Logger logger = Logger.getLogger(RegisterEventListenerProvider.class);
    private final OkHttpClient httpClient = new OkHttpClient();
    private final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private KeycloakSession session;
    private String apiToken;
    private List<String> realms;
    private List<String> clientIds;
    private String apiBaseUrl;
    private String authBaseUrl;
    private String authRealm;
    private String authClientId;
    private String authClientSecret;
    private String learningBaseUrl;
    private String lifterApiKey;
    private String lifterApiSecret;
    private int wpUserId;

    public RegisterEventListenerProvider(KeycloakSession session, List<String> realms, List<String> clientIds,
            String apiBaseUrl, String authBaseUrl, String authRealm, String authClientId, String authClientSecret,
            String learningBaseUrl, String lifterApiKey, String lifterApiSecret) {
        this.session = session;
        this.realms = realms;
        this.clientIds = clientIds;
        this.apiBaseUrl = apiBaseUrl;
        this.authBaseUrl = authBaseUrl;
        this.authRealm = authRealm;
        this.authClientId = authClientId;
        this.authClientSecret = authClientSecret;
        this.learningBaseUrl = learningBaseUrl;
        this.lifterApiKey = lifterApiKey;
        this.lifterApiSecret = lifterApiSecret;
    }

    @Override
    public void onEvent(Event event) {

        // Check if the realm and client ID are in the list to handle
        if (realms != null && !realms.contains(event.getRealmId())
                || clientIds != null && !clientIds.contains(event.getClientId())) {
            logger.info("Realm and client ID not handled. Realm: " + event.getRealmId() + ", Client: "
                    + event.getClientId());
            return;
        }

        // Only handle events of type REGISTER or LOGIN
        if (event.getType() == EventType.REGISTER) {
            MultivaluedMap<String, String> formParameters = session.getContext().getContextObject(HttpRequest.class)
                .getFormParameters();
            String firstName = formParameters.getFirst("firstName");
            String lastName = formParameters.getFirst("lastName");
            handleRegister(event.getUserId(), event.getDetails().get("email"), firstName, lastName, true);
        } else if (event.getType() == EventType.LOGIN) {
            String loginByForm = session.getContext().getUri().getQueryParameters().getFirst("loginByForm");
            UserModel user = session.users().getUserById(event.getUserId(), session.getContext().getRealm());
            Integer nbSessions = 0;
            try {
                nbSessions = Integer.parseInt(user.getFirstAttribute("nb_sessions"));
            } catch (NumberFormatException exc) {
            }

            if ((loginByForm != null && loginByForm.equals("true")) || nbSessions == 0) {
                handleLogin(user, nbSessions);
            }
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Check if the realm is in the list to handle
        if (realms != null && !realms.contains(event.getRealmId())) {
            logger.info("Realm not handled. Realm: " + event.getRealmId());
            return;
        }

        // Only handle CREATE USER events
        if (event.getResourceType() == ResourceType.USER && event.getOperationType() == OperationType.CREATE) {
            JSONObject userDetails = new JSONObject(event.getRepresentation());
            String[] pathParts = event.getResourcePath().split("/");
            String userId = pathParts[pathParts.length - 1];
            handleRegister(userId, userDetails.getString("email"), null, null, false);
        }
    }

    @Override
    public void close() {
    }

    /**
     * Handle login event.
     * The nb_sessions attribute of the user will be increased by 1
     * @param user
     * @param nbSessions
     */
    private void handleLogin(UserModel user, Integer nbSessions) {
        logger.info("Handle Login " + user.getId());
        user.setSingleAttribute("nb_sessions", Integer.toString(nbSessions + 1));
    }

    /**
     * Handle register event.
     * CRM record will be updated or created with the Keycloak user ID if updateCrm is true.
     * User will be created in the learning center.
     * LifterLMS API keys for this user will be created.
     * @param userId
     * @param email
     * @param firstName
     * @param lastName
     * @param updateCrm
     */
    private void handleRegister(String userId, String email, String firstName, String lastName, boolean updateCrm) {
        logger.info("Handle Register " + userId);

        UserModel user = session.users().getUserById(userId, session.getContext().getRealm());
        user.setSingleAttribute("nb_sessions", "0");

        try {
            // Fetch the API token for the Plibo API
            setApiToken();

            if (updateCrm) {
                try {
                    registerUserInCrm(userId, email, firstName, lastName);
                } catch (IOException e) {
                    logger.error("Error updating CRM during REGISTER event: " + e.toString());
                    e.printStackTrace();
                }
            }
    
            try {
                registerUserInLearningCenter(userId, email);
            } catch (IOException e) {
                logger.error("Error creating user in Learning Center during REGISTER event: " + e.toString());
                e.printStackTrace();
            }
    
        } catch (IOException e) {
            logger.error("Error fetching API token during REGISTER event: " + e.toString());
            e.printStackTrace();
        }

        try {
            createUserApiCredentials(userId);
        } catch (IOException e) {
            logger.error("Error creating API key in Learning Center during REGISTER event: " + e.toString());
            e.printStackTrace();
        }
    }

    /**
     * Check if user already exists in CRM. 
     * If it exists, the record will be updated. If not, a new record will be created.
     * @param userId
     * @param email
     * @param firstName
     * @param lastName
     * @throws IOException
     */
    private void registerUserInCrm(String userId, String email, String firstName, String lastName) throws IOException {
        // Fetch the CRM record to check if the user already exists in the CRM
        JSONObject crmRecord = getCrmRecord(email);

        // Create or update the CRM record
        if (crmRecord == null) {
            logger.info("CRM record not found. Creating new one.");
            createCrmRecord(userId, email, firstName, lastName);
        } else {
            logger.info("CRM record found. Updating.");
            String crmId = crmRecord.getJSONObject("record").getString("id");
            JSONObject bodyJSON = new JSONObject();
            bodyJSON.put("Keycloak_ID", userId);
            updateCrmRecord(crmId, bodyJSON);
        }
    }

    /**
     * Register the user in the learning center (wordpress user DB).
     * Add the Wordpress user ID to the Keycloak attributes of the user.
     * @param userId
     * @param email
     * @throws IOException
     */
    private void registerUserInLearningCenter(String userId, String email) throws IOException {
        logger.info("Creating user in learning center (Wordpress).");

        JSONObject bodyJSON = new JSONObject();
        bodyJSON.put("username", email);
        bodyJSON.put("email", email);
        bodyJSON.put("password", getRandomString(20));

        RequestBody body = RequestBody.create(bodyJSON.toString(), JSON);
        String url = apiBaseUrl + "/api/learn/users/";
        Request request = new Request.Builder().url(url).post(body)
                .addHeader("Authorization", "Bearer " + apiToken).build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Error while creating user in Learning center. " + response);
            }

            String responseBody = response.body().string();
            JSONObject responseJSON = new JSONObject(responseBody);
            wpUserId = responseJSON.getInt("id");
            UserModel user = session.users().getUserById(userId, session.getContext().getRealm());
            user.setSingleAttribute("wp_user_id", Integer.toString(wpUserId));
        }
    }

    /**
     * Create user credentials for the LifterLMS API.
     * Add the credentials to the Keycloak attributes of the user.
     * @param userId
     * @throws IOException
     */
    private void createUserApiCredentials(String userId) throws IOException {
        logger.info("Creating user credentials for LifterLMS API.");
        
        JSONObject bodyJSON = new JSONObject();
        bodyJSON.put("user_id", wpUserId);
        bodyJSON.put("permissions", "read");
        bodyJSON.put("description", "API key for user ID " + wpUserId);

        RequestBody body = RequestBody.create(bodyJSON.toString(), JSON);
        String url = learningBaseUrl + "/wp-json/llms/v1/api-keys";
        String credential = Credentials.basic(lifterApiKey, lifterApiSecret);
        Request request = new Request.Builder().url(url).post(body)
                .addHeader("Authorization", credential).build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Error while creating API key in LifterLMS. " + response);
            }

            String responseBody = response.body().string();
            JSONObject responseJSON = new JSONObject(responseBody);
            String userApiKey = responseJSON.getString("consumer_key");
            String userApiSecret = responseJSON.getString("consumer_secret");
            String userCredential = Credentials.basic(userApiKey, userApiSecret);
            UserModel user = session.users().getUserById(userId, session.getContext().getRealm());
            user.setSingleAttribute("lifter_credential", userCredential);
        }
    }

    /**
     * Get the record of the CRM by email.
     * Returns null if the record doesn't exist.
     * @param email
     * @return
     * @throws IOException
     */
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

    /**
     * Create a record in the CRM.
     * @param userId
     * @param email
     * @param firstName
     * @param lastName
     * @throws IOException
     */
    private void createCrmRecord(String userId, String email, String firstName, String lastName) throws IOException {
        JSONObject bodyJSON = new JSONObject();
        bodyJSON.put("Email", email);
        bodyJSON.put("First_Name", firstName);
        bodyJSON.put("Last_Name", lastName);
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

    /**
     * Update a record in the CRM.
     * @param crmId
     * @param bodyJSON
     * @throws IOException
     */
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

    /**
     * Fetch an API token for the Plibo API.
     * @throws IOException
     */
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

    /**
     * Get a random string of letters and numbers with a given length.
     * @param length
     * @return
     */
    private String getRandomString(int length) {
        char[][] charSet = {{'a','z'}, {'0','9'}};
        RandomStringGenerator generator = new RandomStringGenerator.Builder().withinRange(charSet).build();
        return generator.generate(length);
    }
}
# keycloak-register-event-listener

Keycloak event listener that will update the CRM of Plibo when someone registers.  
If a record exists with the same email address, the "Keycloak ID" field will be filled in. If there is no record in the CRM with the given email address, a new record will be created.

## Installation

- Create JAR (with dependencies)

`mvn assembly:assembly -DdescriptorId=jar-with-dependencies`

- Add JAR to `{$KEYCLOAK_HOME}/providers/`
- Add SPI to Keycloack configuration (standalone.xml)  
```
<spi name="eventsListener">
    <provider name="register" enabled="true">
        <properties>
            <property name="realms" value="REALMS_LIST"/>
            <property name="clientIds" value="CLIENTS_LIST"/>
            <property name="apiBaseUrl" value="API_BASE_URL"/>
            <property name="authBaseUrl" value="AUTH_BASE_URL"/>
            <property name="authRealm" value="AUTH_REALM"/>
            <property name="authClientId" value="AUTH_CLIENT_ID"/>
            <property name="authClientSecret" value="AUTH_CLIENT_SECRET"/>
        </properties>
    </provider>
</spi>
```

REALMS_LIST: comma-separated list of realm ID's which the event listener should handle. Removing the property will handle all realms. (caution: realm ID is the first name given to a realm. Changing the name won't change the ID)  
CLIENTS_LIST: comma-separated list of client ID's which the event listener should handle. Removing the property will handle all clients.  
API_BASE_URL: sheme + host of the API endpoint.  
AUTH_BASE_URL: sheme + host of the authorization endpoint to retrieve the access token.  
AUTH_REALM: realm of the authorization endpoint to retrieve the access token.  
AUTH_CLIENT_ID: client ID of the authorization endpoint to retrieve the access token.  
AUTH_CLIENT_SECRET: client secret of the authorization endpoint to retrieve the access token.  

- Restart Keycloak
- Activate event listener in the realms by navigating to Events => Config. Add the 'register' event to 'Event Listeners'
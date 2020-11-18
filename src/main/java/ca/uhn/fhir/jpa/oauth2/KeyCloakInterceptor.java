package ca.uhn.fhir.jpa.oauth2;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.InterceptorAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Interceptor
public class KeyCloakInterceptor extends InterceptorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(KeyCloakInterceptor.class);

    // Const from environment variables
    private static final String OAUTH_ENABLE = System.getenv("OAUTH_ENABLE");
    private static final String OAUTH_URL = System.getenv("OAUTH_URL");

    private static final String BEARER = "BEARER ";

    @Override
    @Hook(Pointcut.SERVER_INCOMING_REQUEST_PRE_PROCESSED)
    public boolean incomingRequestPreProcessed(HttpServletRequest theRequest, HttpServletResponse theResponse) {

        String resourcePath = theRequest.getPathInfo();
        logger.info("Accessing Resource: {}", resourcePath);
        // OAuth authentication is disabled if the environment variable is set to false or not set
        if (!Boolean.parseBoolean(OAUTH_ENABLE)) {
            return true;
        }

        String authHeader = theRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            logger.error("OAuth2 Authentication failure.  No OAuth Token supplied in Authorization Header on Request.");
            throw new AuthenticationException("Unauthorised access to protected resource");
        }

        if (!authHeader.toUpperCase().startsWith(BEARER))
            throw new AuthenticationException("Invalid OAuth Header. Missing Bearer prefix");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authHeader);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(OAUTH_URL, HttpMethod.GET, entity, String.class);

        if (response.getStatusCode()
            .value() != HttpStatus.OK.value()) {
            logger.error("OAuth2 Authentication failure. "
                + "Invalid OAuth Token supplied in Authorization Header on Request.");
            throw new AuthenticationException("Unauthorised access to protected resource");
        }

        logger.debug("Authenticated Access to {}", resourcePath);
        return true;
    }
}

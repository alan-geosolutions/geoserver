package org.geoserver.rest.security;

import org.geoserver.rest.security.xml.AuthFilterChain;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.HtmlLoginFilterChain;
import org.geoserver.security.LogoutFilterChain;
import org.geoserver.test.GeoServerTestSupport;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class AuthenticationFilterChainRestControllerTest extends GeoServerTestSupport {
    private static final String DEFAULT_CHAIN_NAME = "default";
    private static final String TEST_CHAIN_NAME_PREFIX = "TEST-";
    public static final String ROLE_FILTER_NAME = null; // TODO find an actual role
    private static final List<String> TEST_FILTERS = List.of(); // TODO find an actual filter name
    public static final boolean ALLOW_SESSION_CREATION_FLAG = true;
    public static final boolean DISABLED_FLAG = true;
    public static final boolean REQUIRE_SSL_FLAG = true;
    public static final String CLASS_NAME = HtmlLoginFilterChain.class.getName();
    public static final Set<String> HTTP_METHODS = Set.of("GET", "POST");
    public static final List<String> PATTERNS = List.of("/test/path1/*", "/test/path2/*");
    public static final int POSITION = 1;
    public static final boolean MATCH_HTTP_METHOD_FLAG = true;


    private AuthenticationFilterChainRestController controller;


    @Override
    @Before
    public void oneTimeSetUp() throws Exception {
        setValidating(true);
        super.oneTimeSetUp();
        GeoServerSecurityManager securityManager = applicationContext.getBean(GeoServerSecurityManager.class);
        controller = new AuthenticationFilterChainRestController(securityManager);
    }


    @Test
    public void testListFilterChains() throws IOException {
        var response = controller.list();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        var authFilterChainList = response.getBody();
        assertNotNull(authFilterChainList);
        authFilterChainList.getFilterChains().stream()
                .filter(chain -> chain.getName().equals(DEFAULT_CHAIN_NAME))
                .findFirst()
                .ifPresentOrElse(
                        authFilterChain -> {
                            assertEquals(DEFAULT_CHAIN_NAME, authFilterChain.getName());
                        },
                        () -> fail("No default message")
                );
    }

    @Test
    public void testViewFilterChain() throws IOException {
        var response = controller.view(DEFAULT_CHAIN_NAME);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        var authFilterChain = response.getBody();
        assertNotNull(authFilterChain);
        assertEquals(DEFAULT_CHAIN_NAME, authFilterChain.getName());
    }

    @Test
    public void testCreateFilterChain() throws IOException {
        var authFilterChain = createNewAuthFilterChain();
        var response = controller.create(authFilterChain);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        // Check it is accessible
        var viewResponse = controller.view(authFilterChain.getName());
        assertEquals(HttpStatus.OK, viewResponse.getStatusCode());
        var viewFilterChain = viewResponse.getBody();
        assertNotNull(viewFilterChain);
        assertEquals(authFilterChain.getName(), viewFilterChain.getName());
    }

    @Test
    public void testUpdateFilterChain() throws Exception {
        var authFilterChain = createNewAuthFilterChain();
        var response = controller.create(authFilterChain);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        var updatedAuthFilterChain = authFilterChain;
        var updatedResponse = controller.update(updatedAuthFilterChain.getName(), updatedAuthFilterChain);
        assertEquals(HttpStatus.OK, updatedResponse.getStatusCode());
    }

    @Test
    public void testDeleteFilterChain() throws Exception {
        var authFilterChain = createNewAuthFilterChain();
        var response = controller.create(authFilterChain);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());


        var deletedResponse = controller.delete(authFilterChain.getName());
        assertEquals(HttpStatus.OK, deletedResponse.getStatusCode());
    }

    private static AuthFilterChain createNewAuthFilterChain() {
        var authFilterChain = new AuthFilterChain();
        authFilterChain.setName(TEST_CHAIN_NAME_PREFIX + UUID.randomUUID());

        authFilterChain.setRoleFilterName(ROLE_FILTER_NAME);
        authFilterChain.setFilters(TEST_FILTERS);
        authFilterChain.setAllowSessionCreation(ALLOW_SESSION_CREATION_FLAG);
        authFilterChain.setDisabled(DISABLED_FLAG);
        authFilterChain.setRequireSSL(REQUIRE_SSL_FLAG);
        authFilterChain.setClassName(CLASS_NAME);
        authFilterChain.setHttpMethods(HTTP_METHODS);
        authFilterChain.setPatterns(PATTERNS);
        authFilterChain.setPosition(POSITION);
        authFilterChain.setMatchHTTPMethod(MATCH_HTTP_METHOD_FLAG);


        return authFilterChain;
    }




}
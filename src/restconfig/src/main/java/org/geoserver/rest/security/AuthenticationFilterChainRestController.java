package org.geoserver.rest.security;

import com.google.common.base.Strings;
import org.geoserver.rest.RestBaseController;
import org.geoserver.rest.security.xml.AuthFilterChain;
import org.geoserver.rest.security.xml.AuthFilterChainList;
import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.RequestFilterChain;
import org.geoserver.security.config.SecurityManagerConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

@RestController(value = "authenticationFilterChainRestController")
@RequestMapping(path = RestBaseController.ROOT_PATH + "/security/filterChains")
public class AuthenticationFilterChainRestController {
    private final GeoServerSecurityManager securityManager;

    public AuthenticationFilterChainRestController(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'GROUP_ADMIN')")
    @GetMapping(
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            })
    public ResponseEntity<AuthFilterChainList> list() throws IOException {
        var filterChains = listFilterChains();
        var authFilterChainList = new AuthFilterChainList(filterChains);
        return ResponseEntity.ok(authFilterChainList);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'GROUP_ADMIN')")
    @GetMapping(
            value = "/{chainName}",
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            })
    public ResponseEntity<AuthFilterChain> view(@PathVariable("chainName") String chainName) throws IOException {
        var filterChain = viewFilterChain(chainName);
        return ResponseEntity.ok(filterChain);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'GROUP_ADMIN')")
    @PostMapping(
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            },
            consumes = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            }
    )
    public ResponseEntity<AuthFilterChain> create(@RequestBody AuthFilterChain authFilterChain) throws CannotSaveConfig, IOException {
        var filterChain = authFilterChain.toRequestFilterChain();
        var savedFilterChain = saveFilterChain(filterChain, authFilterChain.getPosition());
        return new ResponseEntity<>(savedFilterChain, HttpStatus.CREATED);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'GROUP_ADMIN')")
    @PutMapping(
            value = "/{chainName}",
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            },
            consumes = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            })
    public ResponseEntity<AuthFilterChain> update(@PathVariable("chainName") String chainName, @RequestBody AuthFilterChain authFilterChain) throws IOException {
        var filterChain = authFilterChain.toRequestFilterChain();
        var updatedFilterChain = updateFilterChain(chainName, filterChain, authFilterChain.getPosition());
        return ResponseEntity.ok(updatedFilterChain);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'GROUP_ADMIN')")
    @DeleteMapping(
            value = "/{chainName}",
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
            })
    public ResponseEntity<AuthFilterChain> delete(@PathVariable("chainName") String chainName) throws Exception {
        var deleted = deleteFilterChain(chainName);
        return  ResponseEntity.ok(deleted);
    }


    @ExceptionHandler(IOException.class)
    public ResponseEntity<ErrorResponse> handleRestException(IOException exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(CannotMakeChain.class)
    public ResponseEntity<ErrorResponse> handleRestException(CannotMakeChain exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleRestException(IllegalStateException exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @ExceptionHandler(CannotSaveConfig.class)
    public ResponseEntity<ErrorResponse> handleRestException(CannotSaveConfig exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleRestException(IllegalArgumentException exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NothingToDelete.class)
    public ResponseEntity<ErrorResponse> handleRestException(NothingToDelete exception) {
        // Prepare an error response object
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.GONE.value(),
                exception.getMessage()
        );

        // Return as ResponseEntity with status and body
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }


    // Inner class to model the error response
    public static class ErrorResponse {
        private int status;
        private String message;

        public ErrorResponse(int status, String message) {
            this.status = status;
            this.message = message;
        }

        // Getters and setters for JSON serialization
        public int getStatus() {
            return status;
        }

        public void setStatus(int status) {
            this.status = status;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }


    /// ///////////////////////////////////////////////////////////////////////
    /// Helper methods
    private List<AuthFilterChain> listFilterChains() throws IOException {
        checkState(securityManager != null, "GeoServerSecurityManager not initialized");

        var config = securityManager.loadSecurityConfig();
        var chains = config.getFilterChain().getRequestChains();

        return chains.stream()
                .filter(Objects::nonNull)
                .map(AuthFilterChain::new)
                .peek(chain -> {
                    var filterChain = chains.stream().filter(c -> c.getName().equals(chain.getName())).findFirst().orElse(null);
                    var position = filterChain != null ? chains.indexOf(filterChain) : 0;
                    chain.setPosition(position);
                })
                .collect(Collectors.toList());
    }

    private AuthFilterChain viewFilterChain(String chainName) throws IOException {
        checkState(securityManager != null, "GeoServerSecurityManager not initialized");
        checkArgument(!Strings.isNullOrEmpty(chainName), "chainName is required");

        var config = securityManager.loadSecurityConfig();
        var chain = config.getFilterChain().getRequestChainByName(chainName);
        AuthFilterChain authFilterChain = new AuthFilterChain(chain);
        authFilterChain.setPosition(config.getFilterChain().getRequestChains().indexOf(chain));
        return authFilterChain;
    }

    private AuthFilterChain deleteFilterChain(String chainName) throws IOException {
        checkState(securityManager != null, "GeoServerSecurityManager not initialized");
        checkArgument(!Strings.isNullOrEmpty(chainName), "chainName is required");

        var config = securityManager.loadSecurityConfig();
        var chain = config.getFilterChain();
        var filterChain = chain.getRequestChains().stream()
                .filter(c -> c.getName().equals(chainName))
                .findFirst().orElse(null);
        checkArgument(filterChain != null, "No filter chain with name " + chainName + " found");
        checkArgument(filterChain.canBeRemoved(), "Filter chain " + chainName + " cannot be removed.");

        if (!chain.getRequestChains().remove(filterChain)) {
            throw new NothingToDelete(chainName);
        }
        return saveAndReturnAuthFilterChain(filterChain, config, chain.getRequestChains());
    }

    private AuthFilterChain updateFilterChain(String chainName, RequestFilterChain filterChain, int position) throws CannotSaveConfig, IOException {
        checkState(securityManager != null, "GeoServerSecurityManager not initialized");
        checkArgument(!Strings.isNullOrEmpty(chainName), "chainName is required");
        checkArgument(Objects.equals(filterChain.getName(), chainName), "chainName must be the sams as the name of the filter chain to be updated");
        checkArgument(position >= 0, "position must be greater than or equal to 0");

        var config = securityManager.loadSecurityConfig();
        var chains = config.getFilterChain().getRequestChains();
        checkArgument(position < chains.size(), "position must be less than the number of filter chains");

        var updatedChains = chains.stream()
                .map(chain -> chain.getName().equals(chainName) ? filterChain : chain)
                .collect(Collectors.toList());

        // If position is different to actual position move it
        if (position != updatedChains.indexOf(filterChain)) {
            updatedChains.remove(filterChain);
            updatedChains.add(position, filterChain);
        }

        return saveAndReturnAuthFilterChain(filterChain, config, updatedChains);
    }

    private AuthFilterChain saveFilterChain(RequestFilterChain filterChain, int position) throws IOException {
        checkState(securityManager != null, "GeoServerSecurityManager not initialized");
        checkArgument(Objects.nonNull(filterChain), "filterChain is required");
        checkArgument(position >= 0, "position must be greater than or equal to 0");

        var config = securityManager.loadSecurityConfig();
        var chains = config.getFilterChain().getRequestChains();

        chains.add(position, filterChain);

        return saveAndReturnAuthFilterChain(filterChain, config, chains);
    }

    private AuthFilterChain saveAndReturnAuthFilterChain(RequestFilterChain filterChain, SecurityManagerConfig config, List<RequestFilterChain> chains) {
        var updateGeoServerFilterChains = new GeoServerSecurityFilterChain(chains);
        config.setFilterChain(updateGeoServerFilterChains);
        try {
            securityManager.saveSecurityConfig(config);
        } catch (Exception e) {
            throw new CannotSaveConfig(e);
        }
        securityManager.reload();
        AuthFilterChain authFilterChain = new AuthFilterChain(filterChain);
        authFilterChain.setPosition(chains.indexOf(filterChain));
        return authFilterChain;
    }

    /// ///////////////////////////////////////////////////////////////////////
    /// Helper methods

    public static class CannotMakeChain extends RuntimeException {
        public CannotMakeChain(String className, Exception ex) {
            super("Cannot make class " + className, ex);
        }
    }

    public static class CannotSaveConfig extends RuntimeException {
        public CannotSaveConfig(Exception ex) {
            super("Cannot save the Security configuration ", ex);
        }
    }

    public static class NothingToDelete extends RuntimeException {
        public NothingToDelete(String filterName) {
            super("Cannot delete " + filterName + " as no filter exists");
        }
    }


}

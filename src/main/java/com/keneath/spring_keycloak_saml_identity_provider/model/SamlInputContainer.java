package com.keneath.spring_keycloak_saml_identity_provider.model;

import lombok.Data;

import java.util.Map;

@Data
public class SamlInputContainer {
    private String strIssuer;
    private String strNameID;
    private String strNameQualifier;
    private String sessionId;
    private Integer maxSessionTimeoutInMinutes = 15; // default is 15 minutes
    private Map<String, Object> attributes;
    private String requestId;
    private String recipientUrl;
}

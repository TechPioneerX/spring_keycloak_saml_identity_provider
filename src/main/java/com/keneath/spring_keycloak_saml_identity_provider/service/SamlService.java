package com.keneath.spring_keycloak_saml_identity_provider.service;


import org.opensaml.saml2.core.AuthnRequest;

public interface SamlService {
    AuthnRequest parseSamlRequest(String samlRequestXml);
}

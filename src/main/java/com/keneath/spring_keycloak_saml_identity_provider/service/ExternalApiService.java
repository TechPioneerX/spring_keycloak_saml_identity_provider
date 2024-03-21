package com.keneath.spring_keycloak_saml_identity_provider.service;

import com.keneath.spring_keycloak_saml_identity_provider.model.ExternalUser;

public interface ExternalApiService {
    ExternalUser checkValidateUser(String username, String password );
}

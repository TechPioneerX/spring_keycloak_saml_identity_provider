package com.keneath.spring_keycloak_saml_identity_provider.model;

import lombok.Data;

@Data
public class ExternalUser {
    Integer status; // 1: authenticated, 0: otherwise
    String user;    // username
    String profile; // for example: "admin, ultraadmin, superuser, hyperuser"
    String msg;     // for example: "user authenticated"
}

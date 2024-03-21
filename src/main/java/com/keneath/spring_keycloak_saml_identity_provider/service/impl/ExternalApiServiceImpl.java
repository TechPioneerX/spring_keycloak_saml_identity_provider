package com.keneath.spring_keycloak_saml_identity_provider.service.impl;

import com.keneath.spring_keycloak_saml_identity_provider.model.ExternalUser;
import com.keneath.spring_keycloak_saml_identity_provider.service.ExternalApiService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class ExternalApiServiceImpl implements ExternalApiService {

    @Value("${externalAPI.url.base}")
    private String baseUrl;

    @Value("${externalAPI.url.validateUser}")
    private String validateUrl;

    @Override
    public ExternalUser checkValidateUser(String username, String password ) {

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = String.format("{\"username\": \"%s\", \"password\": \"%s\"}",
                username,
                password );
        HttpEntity<String> request = new HttpEntity<>(body, headers);

        ResponseEntity<ExternalUser> response = restTemplate.postForEntity(
                String.format("%s/%s", baseUrl, validateUrl ),
                request,
                ExternalUser.class);

        return response.getBody();
    }
}

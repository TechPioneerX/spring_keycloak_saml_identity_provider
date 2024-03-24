package com.keneath.spring_keycloak_saml_identity_provider.controller;

import com.keneath.spring_keycloak_saml_identity_provider.Utils.CommonUtil;
import com.keneath.spring_keycloak_saml_identity_provider.Utils.Response;
import com.keneath.spring_keycloak_saml_identity_provider.model.ExternalUser;
import com.keneath.spring_keycloak_saml_identity_provider.service.impl.AssertionBuilder;
import com.keneath.spring_keycloak_saml_identity_provider.service.impl.AssertionSigner;
import com.keneath.spring_keycloak_saml_identity_provider.service.impl.ExternalApiServiceImpl;
import com.keneath.spring_keycloak_saml_identity_provider.service.impl.SamlServiceImpl;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Base64;

@Controller
public class IndexController {

    private static final Logger log = LoggerFactory.getLogger(IndexController.class);

    @Autowired
    private ExternalApiServiceImpl externalApiService;

    @Autowired
    private SamlServiceImpl samlService;

    @Autowired
    private AssertionBuilder assertionBuilder;

    @Autowired
    private AssertionSigner assertionSigner;

    @GetMapping("/loginPage")
    public String showLoginForm(@RequestParam(name = "SAMLRequest", required = false) String samlRequest, Model model) throws Exception {
        if (samlRequest != null) {
            // Decode the Base64-encoded string
            byte[] decodedBytes = Base64.getDecoder().decode(samlRequest);
            String decodedSAMLRequest = CommonUtil.inflate( decodedBytes, true );
            model.addAttribute("SAMLRequest", decodedSAMLRequest);
            model.addAttribute("SAMLRequestOrigin", samlRequest);
        }
        else{
            model.addAttribute("SAMLRequest", null);
            model.addAttribute("SAMLRequestOrigin", null);
        }

        return "loginPage";
    }

    @PostMapping("/loginAction")
    public ResponseEntity<Response<String>> doLogin(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("SAMLRequest") String samlRequest) throws MarshallingException, IOException {

        AuthnRequest authnRequest = samlService.parseSamlRequest( samlRequest );
        if( authnRequest == null )
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new Response<>(
                            HttpStatus.UNAUTHORIZED.value(),
                            false,
                            "User not authenticated."
                    )
            );

        String samlConsumerUrl = authnRequest.getAssertionConsumerServiceURL();
        log.info("\nAssertion Consumer Service URL: \n" + samlConsumerUrl + "\n");

        String requestId = authnRequest.getID();

        ExternalUser externalUser = externalApiService.checkValidateUser( username, password );
        if( externalUser.getStatus() == 0 )
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new Response<>(
                            HttpStatus.UNAUTHORIZED.value(),
                            false,
                            "User not authenticated."
                    )
            );
        log.info("\nUser authenticated: \n" + externalUser.getUser() + "\n");

        // Create assertion
        Assertion assertion = assertionBuilder.buildAssertion(
                username,
                username,
                CommonUtil.uuidGenerator(),
                externalUser.getUser(),
                externalUser.getProfile(),
                requestId,
                samlConsumerUrl);

        // Sign assertion
        String signedAssertion = assertionSigner.signAssertion( assertion );

        // Encode the SAML response using Base64
        String encodedSamlResponse = Base64.getEncoder().encodeToString(signedAssertion.getBytes());

        // Construct the HTML form
        String htmlForm = "<form method=\"post\" action=\"" + samlConsumerUrl + "\" ...>" +
                "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + encodedSamlResponse + "\" />" +
                "<input type=\"hidden\" name=\"RelayState\" value=\"token\" />" +
                // Add other form fields or controls if needed
                "<input type=\"submit\" value=\"Submit\" />" +
                "</form>";

        // Print the HTML form
        System.out.println(htmlForm);

        return ResponseEntity.ok(new Response<>(
                HttpStatus.OK.value(),
                true,
                "User authenticated.",
                samlConsumerUrl
        ));
    }
}

package com.keneath.spring_keycloak_saml_identity_provider.service.impl;

import com.keneath.spring_keycloak_saml_identity_provider.service.SamlService;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;


@Service
public class SamlServiceImpl implements SamlService {
    @Override
    public AuthnRequest parseSamlRequest(String samlRequestXml) {
        try {
            // Initialize OpenSAML
            DefaultBootstrap.bootstrap();

            // Parse XML
            ByteArrayInputStream stream = new ByteArrayInputStream(samlRequestXml.getBytes());
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();
            Document samlDocument = docBuilder.parse(stream);
            Element samlElem = samlDocument.getDocumentElement();

            // Get unmarshaller
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElem);
            if (unmarshaller != null) {
                // Unmarshall the element
                XMLObject requestXmlObj = unmarshaller.unmarshall(samlElem);

                // Ensure the unmarshalled object is an instance of AuthnRequest
                if (requestXmlObj instanceof AuthnRequest) {
                    return (AuthnRequest) requestXmlObj;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}

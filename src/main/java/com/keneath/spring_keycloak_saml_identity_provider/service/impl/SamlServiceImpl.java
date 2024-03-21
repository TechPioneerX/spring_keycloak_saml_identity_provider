package com.keneath.spring_keycloak_saml_identity_provider.service.impl;

import com.keneath.spring_keycloak_saml_identity_provider.service.SamlService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.AuthnRequest;
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
            InitializationService.initialize();

            // Parse XML
            ByteArrayInputStream stream = new ByteArrayInputStream(samlRequestXml.getBytes());
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();
            Document samlDocument = docBuilder.parse(stream);
            Element samlElem = samlDocument.getDocumentElement();

            // Get unmarshaller
            UnmarshallerFactory unmarshallerFactory = org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
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

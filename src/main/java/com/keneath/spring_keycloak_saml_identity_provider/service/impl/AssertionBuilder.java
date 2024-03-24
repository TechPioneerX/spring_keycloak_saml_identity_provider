package com.keneath.spring_keycloak_saml_identity_provider.service.impl;

import com.keneath.spring_keycloak_saml_identity_provider.Utils.CommonUtil;
import com.keneath.spring_keycloak_saml_identity_provider.model.SamlInputContainer;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This is a demo class which creates a valid SAML 2.0 Assertion.
 */

@Service
public class AssertionBuilder {

    private final static Logger logger = LoggerFactory.getLogger(AssertionBuilder.class);

    @Value("${saml.url.idp}")
    private String assertionIssuer;

    @Value("${saml.session.maxSessionTimeoutInMinutes}")
    private Integer maxSessionTimeoutInMinutes;

    private static XMLObjectBuilderFactory builderFactory;


    public Assertion getSamlAssertion(
            String username,
            String nameQualifier,
            String sessionId,
            String firstName,
            String lastName,
            String requestId,
            String recipientUrl ) {

        SamlInputContainer input = new SamlInputContainer();
        input.setStrIssuer(assertionIssuer);
        input.setStrNameID(username);
        input.setStrNameQualifier(nameQualifier);
        input.setSessionId(sessionId);
        input.setMaxSessionTimeoutInMinutes(maxSessionTimeoutInMinutes);
        input.setRequestId( requestId );
        input.setRecipientUrl( recipientUrl );

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("FirstName", firstName);
        customAttributes.put("LastName", lastName);

        input.setAttributes(customAttributes);

        return buildDefaultAssertion( input );
    }

    public static XMLObjectBuilderFactory getSAMLBuilder() throws ConfigurationException {

        if (builderFactory == null) {
            DefaultBootstrap.bootstrap();
            builderFactory = Configuration.getBuilderFactory();
        }

        return builderFactory;
    }

    /**
     * Builds a SAML Attribute of type String
     *
     */
    public Attribute buildStringAttribute(String name, String value, XMLObjectBuilderFactory builderFactory) throws ConfigurationException {
        SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) getSAMLBuilder().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attrFirstName = (Attribute) attrBuilder.buildObject();
        attrFirstName.setName(name);

        // Set custom Attributes
        XMLObjectBuilder stringBuilder = getSAMLBuilder().getBuilder(XSString.TYPE_NAME);
        XSString attrValueFirstName = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attrValueFirstName.setValue(value);

        attrFirstName.getAttributeValues().add(attrValueFirstName);
        return attrFirstName;
    }

    /**
     * Helper method which includes some basic SAML fields which are part of almost every SAML Assertion.
     *
     */
    public Assertion buildDefaultAssertion(SamlInputContainer input) {
        try {
            // Create the NameIdentifier
            SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
            NameID nameId = (NameID) nameIdBuilder.buildObject();
            nameId.setValue(input.getStrNameID());
            nameId.setNameQualifier(input.getStrNameQualifier());
            nameId.setFormat(NameID.UNSPECIFIED);

            // Create the SubjectConfirmation
            SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
            SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();
            DateTime now = new DateTime();
            confirmationMethod.setNotBefore(now);
            confirmationMethod.setNotOnOrAfter(now.plusMinutes(2));
            confirmationMethod.setRecipient(input.getRecipientUrl());
            confirmationMethod.setInResponseTo(input.getRequestId());

            SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
            SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
            subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
            subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

            // Create the Subject
            SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
            Subject subject = (Subject) subjectBuilder.buildObject();

            subject.setNameID(nameId);
            subject.getSubjectConfirmations().add(subjectConfirmation);

            // Create Authentication Statement
            SAMLObjectBuilder authStatementBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
            AuthnStatement authnStatement = (AuthnStatement) authStatementBuilder.buildObject();
            DateTime now2 = new DateTime();
            authnStatement.setAuthnInstant(now2);
            authnStatement.setSessionIndex(input.getSessionId());
            authnStatement.setSessionNotOnOrAfter(now2.plus(input.getMaxSessionTimeoutInMinutes()));

            SAMLObjectBuilder authContextBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
            AuthnContext authnContext = (AuthnContext) authContextBuilder.buildObject();

            SAMLObjectBuilder authContextClassRefBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
            AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authContextClassRefBuilder.buildObject();
            authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"); // TODO not sure exactly about this

            authnContext.setAuthnContextClassRef(authnContextClassRef);
            authnStatement.setAuthnContext(authnContext);

            // Builder Attributes
            SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
            AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();

            // Create the attribute statement
            Map<String, Object> attributes = input.getAttributes();
            if (attributes != null) {
                Set<String> keySet = attributes.keySet();
                for (String key : keySet) {
                    Attribute attrFirstName = buildStringAttribute(key, attributes.get(key).toString(), getSAMLBuilder());
                    attrStatement.getAttributes().add(attrFirstName);
                }
            }

            // Create the do-not-cache condition
            SAMLObjectBuilder doNotCacheConditionBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(OneTimeUse.DEFAULT_ELEMENT_NAME);
            Condition condition = (Condition) doNotCacheConditionBuilder.buildObject();

            SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
            Conditions conditions = (Conditions) conditionsBuilder.buildObject();
            conditions.getConditions().add(condition);

            // Create Issuer
            SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
            Issuer issuer = (Issuer) issuerBuilder.buildObject();
            issuer.setValue(input.getStrIssuer());

            // Create the assertion
            SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) AssertionBuilder.getSAMLBuilder().getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
            Assertion assertion = (Assertion) assertionBuilder.buildObject();
            assertion.setID(CommonUtil.uuidGenerator());
            assertion.setIssuer(issuer);
            assertion.setIssueInstant(now);
            assertion.setVersion(SAMLVersion.VERSION_20);
            assertion.setSubject(subject);
            assertion.getAuthnStatements().add(authnStatement);
            assertion.getAttributeStatements().add(attrStatement);
            assertion.setConditions(conditions);

            return assertion;
        } catch (Exception e) {
            logger.error("Couldn't generate assertion");
        }
        return null;
    }

    public Assertion buildAssertion(String username,
                                    String nameQualifier,
                                    String sessionId,
                                    String firstName,
                                    String lastName,
                                    String requestId,
                                    String recipientUrl) throws MarshallingException {
        Assertion assertion = getSamlAssertion(
                username,
                nameQualifier,
                sessionId,
                firstName,
                lastName,
                requestId,
                recipientUrl
        );
        AssertionMarshaller marshaller = new AssertionMarshaller();
        Element plaintextElement = marshaller.marshall(assertion);
        String assertionString = XMLHelper.nodeToString(plaintextElement);
        logger.info("Generated assertion: \n\n");
        logger.info("\n********************\n" + assertionString + "\n********************\n");
        logger.info("\n");
        return assertion;
    }
}

package com.keneath.spring_keycloak_saml_identity_provider.service.impl;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.liberty.paos.impl.ResponseMarshaller;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Generate selfsigned certificate using following command
 *
 *  keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048
 *
 */
@Service
public class AssertionSigner {

    private final static Logger logger = LoggerFactory.getLogger(AssertionSigner.class);

    @Value("${saml.keystore.password}")
    private String keystorePassword;

    @Value("${saml.keystore.alias}")
    private String certificateAliasName;

    @Autowired
    private ResourceLoader resourceLoader;

    private Credential initializeCredentials() throws IOException {
        KeyStore ks = null;
        char[] password = keystorePassword.toCharArray();

        // Get Default Instance of KeyStore
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            logger.error("Error while Initializing Keystore", e);
        }
        if( ks == null )
            return null;

        // Read and load Keystore
        InputStream is = resourceLoader.getResource("classpath:saml/keystore.jks").getInputStream();
        try {
            ks.load(is, password);
        } catch (Exception e) {
            logger.error("Failed to Load the KeyStore:: ", e);
        }

        // Get Private Key Entry From Certificate
        KeyStore.PrivateKeyEntry pkEntry = null;

        try {
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(
                    certificateAliasName,
                    new KeyStore.PasswordProtection(keystorePassword.toCharArray()));
        } catch (Exception e) {
            logger.error("Failed to Get Private Entry From the keystore", e);
        }
        if( pkEntry == null )
            return null;

        PrivateKey pk = pkEntry.getPrivateKey();
        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);
        credential.setPrivateKey(pk);

        logger.info("Private Key loaded");
        return credential;
    }

    public String signAssertion( Assertion assertion ) throws MarshallingException, IOException {

        // Prepare credential
        Credential signingCredential = initializeCredentials();

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            logger.error("Configuration exception");
        }
        Signature signature = (Signature) Configuration
                .getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);

        // This is also the default if a null SecurityConfiguration is specified
        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        // If null this would result in the default KeyInfoGenerator being used

        try {
            SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
        } catch (Exception e) {
            logger.error("Couldn't prepare signature");
        }

        Response resp = (Response) Configuration
                .getBuilderFactory()
                .getBuilder(Response.DEFAULT_ELEMENT_NAME)
                .buildObject(Response.DEFAULT_ELEMENT_NAME);

        resp.getAssertions().add(assertion);

        resp.setSignature(signature);

        try {
            Configuration.getMarshallerFactory()
                    .getMarshaller(resp)
                    .marshall(resp);
        } catch (MarshallingException e) {
            logger.error("Couldn't marshall");
        }

        try {
            Signer.signObject(signature);
        } catch (org.opensaml.xml.signature.SignatureException e) {
            logger.error("Couldn't sign object");
        }

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element plain = marshaller.marshall(resp);
        // response.setSignature(sign);
        String samlResponse = XMLHelper.nodeToString(plain);

        logger.info("Signed assertion: \n\n");
        logger.info("\n********************\n" + samlResponse + "\n********************\n");
        logger.info("\n");
        return samlResponse;
    }
}

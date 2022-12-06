package org.example;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.tsp.TSPException;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public interface Checker {
    void startCheck() throws InvalidDocumentException, IOException, NoSuchAlgorithmException, TSPException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, SAXException, SignatureException, InvalidKeyException, InvalidKeySpecException, CertificateException;
}

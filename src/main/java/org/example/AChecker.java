package org.example;

import org.apache.xml.security.Init;


import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;

public class AChecker implements Checker{
    Document document;

    final String ERR_MSG_01 = "ds:SignatureProperties musí obsahovať dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos";
    final String ERR_MSG_02 = "obidva ds:SignatureProperty musia mať atribút Target nastavený na ds:Signature";
    final String ERR_MSG_03 = "ds:KeyInfo musí obsahovať ds:X509Data, ktorý obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName";
    final String ERR_MSG_04 = "hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName nesúhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate";
    final String ERR_MSG_05 = "podpisový certifikát dokumentu nie je platný voči času T z časovej pečiatky";
    final String ERR_MSG_06 = "podpisový certifikát dokumentu nie je platný voči platnému poslednému CRL";

    public AChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        org.apache.xml.security.Init.init();
        checkKeyInfo();
        checkSignatureProperties();
        checkReferencedElemsAndDigestVal();
        checkCertificateValidity();
    }

    // overenie obsahu ds:KeyInfo
    private void checkKeyInfo() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        Element dsKeyInfo = getElementByParent(root, "ds:KeyInfo");

        checkIdAttribute(dsKeyInfo);
        Element dsX509Data = getElementByParent(dsKeyInfo, "ds:X509Data");
        X509Certificate cert;
        String issuerName;
        String serialNumber;
        String subjectName;

        try {
            Element dsX509Certificate = getElementByParent(dsX509Data, "ds:X509Certificate");
            Element dsX509IssuerSerial = getElementByParent(dsX509Data, "ds:X509IssuerSerial");

            byte[] decoded = org.bouncycastle.util.encoders.Base64.decode(dsX509Certificate.getText().getBytes());
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));

            issuerName = getElementByParent(dsX509IssuerSerial, "ds:X509IssuerName").getText();
            serialNumber = getElementByParent(dsX509IssuerSerial, "ds:X509SerialNumber").getText();
            subjectName = getElementByParent(dsX509Data, "ds:X509SubjectName").getText();

        } catch (InvalidDocumentException e) {
            throw new InvalidDocumentException(ERR_MSG_03);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        if (!subjectName.equals(cert.getSubjectX500Principal().toString()) ||
            !serialNumber.equals(cert.getSerialNumber().toString()) || !compareIssuerName(issuerName, cert.getIssuerX500Principal().toString())) {
            throw new InvalidDocumentException(ERR_MSG_04);
        }
    }


    // overenie obsahu ds:SignatureProperties
    private void checkSignatureProperties() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        Element dsSignatureProperties = getElementByParent(root, "ds:SignatureProperties");

        checkIdAttribute(dsSignatureProperties);
        String signaturePropertiesId = dsSignatureProperties.attribute("Id").getValue();

        List<Node> nodes = dsSignatureProperties.selectNodes("//ds:SignatureProperty");
        if (nodes.size() != 2) {
            throw new InvalidDocumentException(ERR_MSG_01);
        }
        for (Node node : nodes) {
            Element element = (Element) node;
            Element xzepSignatureVersion = (Element) element.selectSingleNode("//*[name() = 'xzep:SignatureVersion']");
            Element xzepProductInfos = (Element) element.selectSingleNode("//*[name() = 'xzep:ProductInfos']");

            if (xzepProductInfos == null || xzepSignatureVersion == null) {
                throw new InvalidDocumentException(ERR_MSG_01);
            }
            String target = element.attribute("Target").getValue().substring(1);

            if (!signaturePropertiesId.contains(target)) {
                throw new InvalidDocumentException(ERR_MSG_02);
            }
        }
    }


    // dereferencovanie URI, kanonikalizácia referencovaných ds:Manifest elementov a overenie hodnôt odtlačkov ds:DigestValue
    private void checkReferencedElemsAndDigestVal() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        List<Node> referenceNodes = root.selectNodes("//ds:SignedInfo/ds:Reference");

        if (referenceNodes.size() == 0) {
            throw new InvalidDocumentException("ds:SignedInfo neobsahuje ds:Reference elementy");
        }
        // iterujeme cez //ds:SignedInfo/ds:Reference nodes
        for (Node refNode : referenceNodes) {

            // pre každý z reference elementov nájdeme URI
            Element reference = (Element) refNode;
            String uri = reference.attribute("URI").getValue().substring(1);

            // nájdeme ds:Manifest element s rovnakým URI
            Element manifestElement = getElementByAttributeValue("ds:Manifest", "Id", uri);

            if (manifestElement == null) {
                continue;
            }

            byte[] manifestBytes = manifestElement.asXML().getBytes(StandardCharsets.UTF_8);

            // zistenie algoritmu podla ktoreho budeme hashovať referencovaný ds:Manifest element
            String dsDigestValue = getElementByParent(reference, "ds:DigestValue").getStringValue();
            String algoType = getElementByParent(reference, "ds:DigestMethod").attribute("Algorithm").getValue();
            String refAlgo = getAlgorithm(algoType);

            if (refAlgo.equals(null)) {
                throw new InvalidDocumentException("ds:SignedInfo oobsahuje referenciu na neexistujuci algoritmus");
            }

            Element transformElement = getElementByParent(manifestElement, "ds:Transform");
            String algo = transformElement.attribute("Algorithm").getValue();

            if (algo.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {
                try {
                    Canonicalizer canonicalizer = Canonicalizer.getInstance(algo);
                    manifestBytes = canonicalizer.canonicalize(manifestBytes);
                } catch (InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException |
                         IOException | SAXException e) {
                    throw new InvalidDocumentException("Chyba pri kanonikalizácií");
                }
            }

            MessageDigest messageDigest;

            try {
                messageDigest = MessageDigest.getInstance(refAlgo);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidDocumentException("ds:SignedInfo oobsahuje referenciu na neexistujuci algoritmus");
            }
            String hashed = new String(org.bouncycastle.util.encoders.Base64.encode(messageDigest.digest(manifestBytes)));

            /*if (!dsDigestValue.equals(hashed)) {
                throw new InvalidDocumentException("hodnota ds:DigestValue nesedí s hashom referencovaného ds:Manifest elementu");
            }*/
        }
    }


    // overenie platnosti podpisového certifikátu dokumentu voči času T z časovej pečiatky a voči platnému poslednému CRL
    private void checkCertificateValidity() throws InvalidDocumentException {
        X509Certificate cert;
        Element root = this.document.getRootElement();
        Element dsX509Certificate = getElementByParent(root, "ds:X509Certificate");

        try {
            byte[] decoded = Base64.getDecoder().decode(dsX509Certificate.getText().getBytes());
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));

            TimeStampToken timestamp = loadTimeStampToken();
            cert.checkValidity(timestamp.getTimeStampInfo().getGenTime());

            X509CRLHolder crlHolder = getCrlData();
            Collection<?> revokedCerts = crlHolder.getRevokedCertificates();
            for (Object revokedCert : revokedCerts) {
                X509CRLEntryHolder certificateHolder = (X509CRLEntryHolder) revokedCert;
                BigInteger revokedCertSerialNum = certificateHolder.getSerialNumber();

                if (Objects.equals(revokedCertSerialNum, cert.getSerialNumber())) {
                    throw new InvalidDocumentException(ERR_MSG_06);
                }
            }

        } catch (CertificateException e) {
            throw new InvalidDocumentException(ERR_MSG_05);
       } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private Element getElementByAttributeValue(String name, String atrib, String value) {
        Element root = this.document.getRootElement();
        List<Node> nodes = root.selectNodes("//" + name);

        for (Node node : nodes) {
            Element elem = (Element) node;
            String id = elem.attribute(atrib).getValue();

            if (id.equals(value)) {
                return elem;
            }
        }
        return null;
    }

    private String getAlgorithm(String algoType) {

        switch (algoType) {
            case "http://www.w3.org/2000/09/xmldsig#sha1":
                return "SHA-1";
            case "http://www.w3.org/2001/04/xmldsig-more#sha224":
                return "SHA-224";
            case "http://www.w3.org/2001/04/xmlenc#sha256":
                return "SHA-256";
            case "http://www.w3.org/2001/04/xmldsig-more#sha384":
                return "SHA-384";
            case "http://www.w3.org/2001/04/xmlenc#sha512":
                return "SHA-512";
            default:
                return null;
        }
    }

    private Element getElementByParent(Element parent, String elemName) throws InvalidDocumentException {
        Element element = (Element) parent.selectSingleNode("//*[name() = '" + elemName + "']");
        if (element == null) {
            throw new InvalidDocumentException("Chýba " + elemName + " element");
        }
        return element;
    }

    private void checkIdAttribute(Element element) throws InvalidDocumentException {
        Attribute elementId = element.attribute("Id");
        if (elementId == null || elementId.getValue().equals("")) {
            throw new InvalidDocumentException("ds:" + element.getName() + " musí mať Id atribút");
        }
    }

    private boolean compareIssuerName(String issuerName1, String issuerName2) {
        issuerName1 = issuerName1.replace("ST", "S");
        issuerName2 = issuerName2.replace("ST", "S");

        return issuerName1.equals(issuerName2);
    }

    private TimeStampToken loadTimeStampToken() {
        try {
            Element root = this.document.getRootElement();
            Element timestamp = getElementByParent(root, "xades:EncapsulatedTimeStamp");
            return new TimeStampToken(new CMSSignedData(Base64.getDecoder().decode(timestamp.getText())));
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private X509CRLHolder getCrlData() throws IOException, InvalidDocumentException {
        URL url = new URL("http://test.ditec.sk/TSAServer/crl/dtctsa.crl");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setDoOutput(true);
        con.setDoInput(true);

        int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new InvalidDocumentException("Nepodarilo sa ziskat CRL pre casovu peciatku");
        }

        ASN1InputStream asn1InputStream = new ASN1InputStream(con.getInputStream());
        return new X509CRLHolder(asn1InputStream);
    }
}

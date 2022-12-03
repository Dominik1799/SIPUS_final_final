package org.example;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.Base64;
import java.util.List;

public class AChecker implements Checker{
    Document document;

    final String ERR_MSG_01 = "ds:SignatureProperties musí obsahovať dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos";
    final String ERR_MSG_02 = "obidva ds:SignatureProperty musia mať atribút Target nastavený na ds:Signature";
    final String ERR_MSG_03 = "ds:KeyInfo musí obsahovať ds:X509Data, ktorý obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName";
    final String ERR_MSG_04 = "hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName nesúhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate";
    final String ERR_MSG_05 = "podpisový certifikát dokumentu nie je platný voči času T z časovej pečiatky ";

    public AChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
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

            byte[] decoded = Base64.getDecoder().decode(dsX509Certificate.getText().getBytes());
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

        } catch (CertificateException e) {
            throw new InvalidDocumentException(ERR_MSG_05);
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
}

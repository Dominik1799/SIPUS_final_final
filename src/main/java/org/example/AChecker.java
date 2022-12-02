package org.example;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;

import java.util.List;

public class AChecker implements Checker{
    Document document;

    final String ERR_MSG_01 = "ds:SignatureProperties musí obsahovať dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos";
    final String ERR_MSG_02 = "obidva ds:SignatureProperty musia mať atribút Target nastavený na ds:Signature";
    final String ERR_MSG_03 = "ds:KeyInfo musí obsahovať ds:X509Data, ktorý obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName";

    public AChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        checkKeyInfo();
        checkSignatureProperties();
    }

    private void checkKeyInfo() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        Element dsKeyInfo = getElementByParent(root, "ds:KeyInfo");

        checkIdAttribute(dsKeyInfo);
        Element dsX509Data = getElementByParent(dsKeyInfo, "ds:X509Data");

        try {
            Element dsX509Certificate = getElementByParent(dsX509Data, "ds:X509Certificate");
            Element dsX509IssuerSerial = getElementByParent(dsX509Data, "ds:X509IssuerSerial");
            Element dsX509SubjectName = getElementByParent(dsX509Data, "ds:X509SubjectName");

        } catch (InvalidDocumentException e) {
            throw new InvalidDocumentException(ERR_MSG_03);
        }
    }

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
}

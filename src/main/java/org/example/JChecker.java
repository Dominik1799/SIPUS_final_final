package org.example;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Namespace;

public class JChecker implements Checker{

    Document document;

    public JChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        checkDsSignature();
        // checkDsSignatureValue();
    }

    private void checkDsSignature() throws InvalidDocumentException {
        String REQUIRED_NAMESPACE_PREFIX = "ds";
        String EXPECTED_DS_NAMESPACE_URI = "http://www.w3.org/2000/09/xmldsig#";

        Element root = this.document.getRootElement();
        Element dsSignature = (Element) root.selectSingleNode("//*[name() = 'ds:Signature']");
        if (dsSignature == null) {
            throw new InvalidDocumentException("Chýba ds:Signature");
        }
        Attribute dsSignatureId = dsSignature.attribute("Id");
        // TODO: can be blank???
        if (dsSignatureId == null || dsSignatureId.getValue().equals("")) {
            throw new InvalidDocumentException("ds:Signature musí mať Id atribút");
        }


        Namespace xmlnsDs = dsSignature.getNamespaceForPrefix(REQUIRED_NAMESPACE_PREFIX);
        // TODO: required URI check???
        if (xmlnsDs == null || !xmlnsDs.getURI().equals(EXPECTED_DS_NAMESPACE_URI)) {
            throw new InvalidDocumentException("ds:Signature musí mať špecifikovaný namespace xmlns:ds");
        }
    }

    private void checkDsSignatureValue() throws InvalidDocumentException {

    }
}

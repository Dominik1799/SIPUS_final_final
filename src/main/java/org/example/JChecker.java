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
        checkDsSignatureValue();
    }

    // specifikacia XADESU strana 17
    private void checkDsSignature() throws InvalidDocumentException {
        String REQUIRED_NAMESPACE_PREFIX = "ds";
        String EXPECTED_DS_NAMESPACE_URI = "http://www.w3.org/2000/09/xmldsig#";

        Element root = this.document.getRootElement();
        Element dsSignature = (Element) root.selectSingleNode("//*[name() = 'ds:Signature']");
        if (dsSignature == null) {
            throw new InvalidDocumentException("Chýba ds:Signature element");
        }

        Attribute dsSignatureId = dsSignature.attribute("Id");
        // TODO: Id - ds:Signature element je referencovaný z elementu xades:QualifyingProperties, atribút Target(check reference)???
        // tested on documents 03(valid) and 05(invalid)
        if (dsSignatureId == null || dsSignatureId.getValue().equals("")) {
            throw new InvalidDocumentException("ds:Signature musí mať Id atribút");
        }

        Namespace xmlnsDs = dsSignature.getNamespaceForPrefix(REQUIRED_NAMESPACE_PREFIX);
        // tested on documents 03(valid), missing not valid document according to this rule
        if (xmlnsDs == null || !xmlnsDs.getURI().equals(EXPECTED_DS_NAMESPACE_URI)) {
            throw new InvalidDocumentException("ds:Signature musí mať špecifikovaný namespace xmlns:ds");
        }
    }

    // specifikacia XADESU strana 24
    private void checkDsSignatureValue() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        Element dsSignatureValue = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureValue']");

        if (dsSignatureValue == null) {
            throw new InvalidDocumentException("Chýba ds:SignatureValue element");
        }

        Attribute dsSignatureValueId = dsSignatureValue.attribute("Id");
        // TODO: Id – element ds:SignatureValue je referencovaný z elementu xades:SignatureTimeStamp(check reference)???
        // tested on documents 03(valid) and 06(invalid)
        if (dsSignatureValueId == null || dsSignatureValueId.getValue().equals("")) {
           throw new InvalidDocumentException("ds:SignatureValue – musí mať Id atribút");
        }
    }
}

package org.example;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Namespace;

import java.util.HashMap;
import java.util.HashSet;

public class DChecker implements Checker {

    Document document;

    public DChecker(Document document) {
        this.document = document;
    }

    public void startCheck() throws InvalidDocumentException {
        this.checkRootAttributes();
        this.checkValidAlgorithmURI();
    }

    // specifikacia XADESU strana 16
    private void checkRootAttributes() throws InvalidDocumentException {
        String EXPECTED_XZEP = "http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0";
        String EXPECTED_DS = "http://www.w3.org/2000/09/xmldsig#";
        HashMap<String, String> checkMap = new HashMap<>();
        checkMap.put("xzep", EXPECTED_XZEP);
        checkMap.put("ds", EXPECTED_DS);

        Element root = this.document.getRootElement();
        for (Namespace ns : root.declaredNamespaces()) {
            if (checkMap.containsKey(ns.getPrefix()) && !checkMap.get(ns.getPrefix()).equals(ns.getURI())) {
                throw new InvalidDocumentException("Koreňový element musí obsahovať atribúty xmlns:xzep a xmlns:ds podľa profilu XADES_ZEP.");
            }
        }
    }
    // specifikacia XADESU strana 22 (signatureMethod, kap. 4.3.1.2) + na konci dokumentu algoritmy v tabulke
    // strana 22 (canonMethod, kap 4.3.1.1)
    private void checkValidAlgorithmURI() throws InvalidDocumentException {
        String ERROR_MSG = "Kontrola obsahu ds:SignatureMethod a ds:CanonicalizationMethod – musia obsahovať URI niektorého z podporovaných algoritmov pre dané elementy podľa profilu XAdES_ZEP";
        String CANON_ALGORITHM = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        HashSet<String> checkSet = new HashSet<>();
        checkSet.add("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
        checkSet.add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        checkSet.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        checkSet.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
        checkSet.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
        Element root = this.document.getRootElement();
        Element signatureMethod = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureMethod']");
        Element canonicalizationMethod = (Element) root.selectSingleNode("//*[name() = 'ds:CanonicalizationMethod']");
        // first check SignatureMethod
        if (signatureMethod == null || canonicalizationMethod == null) {
            throw new InvalidDocumentException(ERROR_MSG);
        }
        Attribute signatureAttribute = signatureMethod.attribute("Algorithm");
        if (signatureAttribute == null || !checkSet.contains(signatureAttribute.getValue())) {
            throw new InvalidDocumentException(ERROR_MSG);
        }
        // now check CanonicalizationMethod
        Attribute canonAttribute = canonicalizationMethod.attribute("Algorithm");
        if (canonAttribute == null || !CANON_ALGORITHM.equals(canonAttribute.getValue())) {
            throw new InvalidDocumentException(ERROR_MSG);
        }

    }
}

package org.example;

import org.dom4j.*;

import java.util.*;

public class JChecker implements Checker{

    Document document;

    public JChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        checkDsSignature();
        checkDsSignatureValue();
        checkDsManifestElements();
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
        // tested on documents 03(valid) and 06(invalid)
        if (dsSignatureValueId == null || dsSignatureValueId.getValue().equals("")) {
           throw new InvalidDocumentException("ds:SignatureValue – musí mať Id atribút");
        }
    }

    // specifikacia strana 25
    private void checkDsManifestElements() throws InvalidDocumentException {
        String CANONICALIZATION_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        String BASE64_URI = "http://www.w3.org/2000/09/xmldsig#base64 ";

        ArrayList<String> validTransformAlgorithms = new ArrayList<>(2);
        validTransformAlgorithms.add(CANONICALIZATION_URI);
        validTransformAlgorithms.add(BASE64_URI);

        Element root =  this.document.getRootElement();
        List<Node> manifestNodes = root.selectNodes("//*[name() = 'ds:Manifest']");

        for (Node manifestNode : manifestNodes) {
            // check if manifest has Id attribute
            Element manifest = (Element) manifestNode;
            Attribute manifestId = manifest.attribute("Id");

            if (manifestId == null || manifestId.getValue().equals("")) {
                throw new InvalidDocumentException("každý ds:Manifest element musí mať Id atribút");
            }

            checkDsTransforms(manifest);
            checkDsDigestMethod(manifest);
            // TODO: overenie hodnoty Type atribútu voči profilu XAdES_ZEP - nie je ako atribut v ds:Manifest ale v ds:Manifest > ds:Reference
        }
    }

    // specifikacia strana 26
    private void checkDsTransforms(Element manifest) throws InvalidDocumentException {
        ArrayList<String> validTransformAlgorithms = new ArrayList<>(2);
        validTransformAlgorithms.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        validTransformAlgorithms.add("http://www.w3.org/2000/09/xmldsig#base64");

        // check if all ds:Transform elements in ds:Transforms element contains valid transformation algorithm
        Element dsTransforms = (Element) manifest.selectSingleNode("//*[name() = 'ds:Transforms']");

        if (dsTransforms == null) {
            throw new InvalidDocumentException("ds:Transforms musí byť z množiny podporovaných algoritmov pre" +
                    " daný element podľa profilu XAdES_ZEP (ds:Manifest neobsahuje ds:Transforms)");
        }

        for (Iterator<Element> it = dsTransforms.elementIterator("//*[name() = 'ds:Transform']"); it.hasNext();) {
            Element dsTransform = it.next();
            Attribute dsTransformAlgorithm = dsTransform.attribute("Algorithm");

            if (dsTransformAlgorithm == null) {
                throw new InvalidDocumentException("ds:Transforms musí byť z množiny podporovaných algoritmov pre" +
                        " daný element podľa profilu XAdES_ZEP (nema Algorithm atribut)");
            }

            String dsTransformAlgorithmValue = dsTransformAlgorithm.getValue();
            if (!validTransformAlgorithms.contains(dsTransformAlgorithmValue)) {
                throw new InvalidDocumentException("ds:Transforms musí byť z množiny podporovaných algoritmov pre" +
                        " daný element podľa profilu XAdES_ZEP");
            }
        }
    }

    // specifikacia strana 27 a 37
    private void checkDsDigestMethod(Element manifest) throws InvalidDocumentException {
        String[] validDigestMethodAlgorithms = {
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmldsig-more#sha224",
                "https://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512"
        };
        List<String> validDigestMethodAlgsList = Arrays.asList(validDigestMethodAlgorithms);

        Element dsDigestMethod = (Element) manifest.selectSingleNode("//*[name() = 'ds:DigestMethod']");
        if (dsDigestMethod == null) {
            throw new InvalidDocumentException("ds:DigestMethod – musí obsahovať URI niektorého z podporovaných" +
                    " algoritmov podľa profilu XAdES_ZEP (chyba ds:DigestMethod)");
        }

        Attribute dsDigestMethodAlgorithm =  dsDigestMethod.attribute("Algorithm");

        if (dsDigestMethodAlgorithm == null) {
            throw new InvalidDocumentException("ds:DigestMethod – musí obsahovať URI niektorého z podporovaných" +
                    " algoritmov podľa profilu XAdES_ZEP (chyba Algorithm attribut)");
        }

        String dsDigestMethodAlgorithmValue = dsDigestMethodAlgorithm.getValue();
        if (!validDigestMethodAlgsList.contains(dsDigestMethodAlgorithmValue)) {
            throw new InvalidDocumentException("ds:DigestMethod – musí obsahovať URI niektorého z podporovaných" +
                    " algoritmov podľa profilu XAdES_ZEP");
        }
    }
}

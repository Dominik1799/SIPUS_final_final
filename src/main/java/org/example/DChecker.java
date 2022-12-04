package org.example;

import org.dom4j.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class DChecker implements Checker {

    Document document;

    public DChecker(Document document) {
        this.document = document;
    }

    public void startCheck() throws InvalidDocumentException {
        this.checkSignedInfoReferenceExistence(); // zle doku 7,9
        this.checkSignedInfoReferences(); // zle doku 3
        this.checkRootAttributes(); // zle doku 1
        this.checkValidAlgorithmURI(); // zle doku 2
    }

    // NOTE: element xades:DataObjectType neexistuje aj ked podla prirucky tam je. mozno je mysleny element xades:DataObjectFormat?
    // zle dokumenty: 7 a 9
    public void checkSignedInfoReferenceExistence() throws InvalidDocumentException {
        String ERROR_MSG = "Overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type voci profilu XAdES_ZEP pre ds:KeyInfo, ds:SignatureProperties, xades:SignedProperties. Všetky ostatné referencie v rámci ds:SignedInfo musia byť referenciami na ds:Manifest elementy";
        HashMap<String, Boolean> referenceExistenceCheck = new HashMap<>();
        referenceExistenceCheck.put("http://www.w3.org/2000/09/xmldsig#Object", Boolean.FALSE);
        referenceExistenceCheck.put("http://www.w3.org/2000/09/xmldsig#SignatureProperties", Boolean.FALSE);
        referenceExistenceCheck.put("http://uri.etsi.org/01903#SignedProperties", Boolean.FALSE);
        referenceExistenceCheck.put("http://www.w3.org/2000/09/xmldsig#Manifest", Boolean.FALSE);
        HashMap<String, String> expectedElementsCheck = new HashMap<>();
        expectedElementsCheck.put("http://www.w3.org/2000/09/xmldsig#Object", "ds:KeyInfo");
        expectedElementsCheck.put("http://www.w3.org/2000/09/xmldsig#SignatureProperties", "ds:SignatureProperties");
        expectedElementsCheck.put("http://uri.etsi.org/01903#SignedProperties", "xades:SignedProperties");
        expectedElementsCheck.put("http://www.w3.org/2000/09/xmldsig#Manifest", "ds:Manifest");
        Element root = this.document.getRootElement();
        Element signedInfo = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo']");
        List<Node> references = signedInfo.selectNodes("//ds:SignedInfo/ds:Reference");
        for (Node reference : references) {
            // first check if required references exist
            Element r = (Element) reference;
            if (r.attribute("Type") == null || !referenceExistenceCheck.containsKey(r.attribute("Type").getValue())
                    || r.attribute("URI") == null) {
                throw new InvalidDocumentException(ERROR_MSG);
            }
            // set flag for correct type
            referenceExistenceCheck.put(r.attribute("Type").getValue(), Boolean.TRUE);
            // now check if it points to a correct element
            String query = String.format("//*[@Id = '%s']", r.attribute("URI").getValue().replace("#", ""));
            Element referencedElement = (Element) root.selectSingleNode(query);
            // reference element has attribute Type. if this attribute points to correct element, continue. if not, throw exception
            if (referencedElement == null || !referencedElement.getQualifiedName().equals(expectedElementsCheck.get(r.attribute("Type").getValue()))) {
                throw new InvalidDocumentException(ERROR_MSG);
            }
            // now check if Id of a reference is correctly referenced by xades:DataObjectFormat element
            // but only for manifest type, other objects are not referenced
            if (!expectedElementsCheck.get(r.attribute("Type").getValue()).equals("ds:Manifest")) {
                continue;
            }
            query = String.format("//*[@ObjectReference = '#%s']", r.attribute("Id").getValue());
            Element referencingElement = (Element) root.selectSingleNode(query);
            if (referencingElement == null || !referencingElement.getQualifiedName().equals("xades:DataObjectFormat")){
                // this might not be necessary??
                throw new InvalidDocumentException(ERROR_MSG);
            }
        }
        // now check referenceExistenceCheck if all flags are set to true
        // however, maybe ds:Manifest does not have to exist in document? unclear in specification, thats why its
        // separate if condition, so we can easily delete it
        for (String key : referenceExistenceCheck.keySet()) {
            // if we did not find this type of reference, throw error
            if (!referenceExistenceCheck.get(key)) {
                // uncomment this if condition if ds:Manifest element is not necessary
//                if (key.equals("http://www.w3.org/2000/09/xmldsig#Manifest")) {
//                    continue;
//                }
                throw new InvalidDocumentException(ERROR_MSG);
            }
        }
    }



    private void checkSignedInfoReferences() throws InvalidDocumentException {
        String ERROR_MSG = "kontrola obsahu ds:Transforms a ds:DigestMethod vo všetkých referenciách v ds:SignedInfo – musia obsahovať URI niektorého z podporovaných algoritmov podľa profilu XAdES_ZEP";
        String VALID_TRANSFORM_ALGO = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        Element root = this.document.getRootElement();
        Element signedInfo = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo']");
        List<Node> transforms = signedInfo.selectNodes("//*[name() = 'ds:Transform']");
        List<Node> digestMethods = signedInfo.selectNodes("//*[name() = 'ds:DigestMethod']");
        // check signed info
        for (Node transform : transforms) {
            Element t = (Element) transform;
            Attribute algo = t.attribute("Algorithm");
            if (algo == null || !algo.getValue().equals(VALID_TRANSFORM_ALGO)) {
                throw new InvalidDocumentException(ERROR_MSG);
            }
        }
        // now check DigestMethod
        HashSet<String> checkSet = new HashSet<>();
        checkSet.add("http://www.w3.org/2000/09/xmldsig#sha1");
        checkSet.add("http://www.w3.org/2001/04/xmldsigmore#sha224");
        checkSet.add("http://www.w3.org/2001/04/xmldsigmore#sha384");
        checkSet.add("http://www.w3.org/2001/04/xmlenc#sha512");
        checkSet.add("http://www.w3.org/2001/04/xmlenc#sha256");
        for (Node method : digestMethods) {
            Element m = (Element) method;
            Attribute algo = m.attribute("Algorithm");
            if (algo == null || !checkSet.contains(algo.getValue())) {
                throw new InvalidDocumentException(ERROR_MSG);
            }
        }
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
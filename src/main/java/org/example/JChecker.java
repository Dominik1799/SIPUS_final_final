package org.example;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.dom4j.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class JChecker implements Checker{

    Document document;

    public JChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException, IOException, NoSuchAlgorithmException, TSPException {
        // checkDsSignature();
        // checkDsSignatureValue();
        checkDsManifestElements();
        // checkTimestamp();
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

    // not valid:
    // valid: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
    // specifikacia strana 27
    private void checkDsManifestElements() throws InvalidDocumentException {
        Element root =  this.document.getRootElement();
        List<Node> manifestNodes = root.selectNodes("//*[name() = 'ds:Manifest']");

        for (Node manifestNode : manifestNodes) {
            // check if manifest has Id attribute
            Element manifest = (Element) manifestNode;
            Attribute manifestId = manifest.attribute("Id");

            if (manifestId == null || manifestId.getValue().equals("")) {
                throw new InvalidDocumentException("každý ds:Manifest element musí mať Id atribút");
            }

            List<Node> referenceNodes = manifest.selectNodes("ds:Reference");
            if (referenceNodes.size() != 1) {
                throw new InvalidDocumentException("každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object");
            }
            Element reference = (Element) referenceNodes.get(0);

            checkDsTransforms(reference);
            checkDsDigestMethod(reference);
            checkDsReferenceTypeAttribute(reference);
            checkDsReferenceURIToDsObject(reference);
        }
    }

    // specifikacia strana 26
    private void checkDsTransforms(Element reference) throws InvalidDocumentException {
        ArrayList<String> validTransformAlgorithms = new ArrayList<>(2);
        validTransformAlgorithms.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        validTransformAlgorithms.add("http://www.w3.org/2000/09/xmldsig#base64");

        // check if all ds:Transform elements in ds:Transforms element contains valid transformation algorithm
        Element dsTransforms = (Element) reference.selectSingleNode("ds:Transforms");
        if (dsTransforms == null) {
            throw new InvalidDocumentException("ds:Transforms musí byť z množiny podporovaných algoritmov pre" +
                    " daný element podľa profilu XAdES_ZEP (ds:Manifest neobsahuje ds:Transforms)");
        }

        List<Node> dsTransformElements = dsTransforms.selectNodes("ds:Transform");
        if (dsTransformElements.size() == 0) {
            throw new InvalidDocumentException("ds:Transforms musí byť z množiny podporovaných algoritmov pre" +
                    " daný element podľa profilu XAdES_ZEP (ds:Transforms neobsahuje ds:Transform)");
        }

        for (Node dsTransform : dsTransformElements) {
            Attribute dsTransformAlgorithm =  ((Element)dsTransform).attribute("Algorithm");

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
    private void checkDsDigestMethod(Element reference) throws InvalidDocumentException {
        String[] validDigestMethodAlgorithms = {
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmldsig-more#sha224",
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512"
        };
        List<String> validDigestMethodAlgsList = Arrays.asList(validDigestMethodAlgorithms);

        Element dsDigestMethod = (Element) reference.selectSingleNode("ds:DigestMethod");
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

    private void checkDsReferenceTypeAttribute(Element reference) throws InvalidDocumentException {
        Attribute referenceType = reference.attribute("Type");

        if (referenceType == null || !referenceType.getValue().equals("http://www.w3.org/2000/09/xmldsig#Object")) {
            throw new InvalidDocumentException("overenie ds:Manifest elementov: overenie hodnoty Type atribútu voči profilu XAdES_ZEP");
        }
    }

    private void checkDsReferenceURIToDsObject(Element reference) throws InvalidDocumentException {
        Attribute referenceURI = reference.attribute("URI");

        if (referenceURI == null) {
            throw new InvalidDocumentException("každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object");
        }

        String valueURI = referenceURI.getValue();
        Element dsObject = (Element) reference.selectSingleNode("//ds:Object[@Id=substring-after(" + "'" + valueURI + "'" + ", '#')]");

        if (dsObject == null) {
            throw new InvalidDocumentException("každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object");
        }
    }

    private void checkTimestamp() throws InvalidDocumentException, TSPException, IOException, NoSuchAlgorithmException {
        Element root =  this.document.getRootElement();
        Element encapsulatedTimeStamp = (Element) root.selectSingleNode("//*[name() = 'xades:EncapsulatedTimeStamp']");

        if (encapsulatedTimeStamp == null) {
            throw new InvalidDocumentException("overenie platnosti podpisového certifikátu časovej pečiatky voči času" +
                    " UtcNow a voči platnému poslednému CRL (neobsahuje xades:EncapsulatedTimeStamp)");
        }

        String base64TimestampToken = encapsulatedTimeStamp.getStringValue();
        byte[] decodedTimestampToken = Base64.getDecoder().decode(base64TimestampToken);
        // it is only possible to get token from bytes
        TimeStampToken token = new TimeStampToken(ContentInfo.getInstance(decodedTimestampToken));

        // TODO: overit overenie platnosti podpisového certifikátu časovej pečiatky voči času UtcNow a voči platnému poslednému CRL
        // checkSignedCertExpiry(token);

        compareMessageImprintWithDsSignatureValue(token, root);
    }

    private void checkSignedCertExpiry(TimeStampToken token) throws InvalidDocumentException {
        BigInteger signerSerialNum = token.getSID().getSerialNumber();

        Store<X509CertificateHolder> timestampCerts = token.getCertificates();
        Iterator<?> iterator = ((CollectionStore<?>) timestampCerts).iterator();
        X509CertificateHolder signerCert = null;

        while (iterator.hasNext()) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) iterator.next();

            if (Objects.equals(certificateHolder.getSerialNumber(), signerSerialNum)) {
                signerCert = certificateHolder;
            }
        }

        if (signerCert == null) {
            throw new InvalidDocumentException("overenie platnosti podpisového certifikátu časovej pečiatky voči času" +
                    " UtcNow a voči platnému poslednému CRL (nenasiel sa certifikat s " + signerSerialNum + " seriovym cislom");
        }
    }

    // TODO: all documents are valid according this rule
    private void compareMessageImprintWithDsSignatureValue(TimeStampToken token, Element root) throws NoSuchAlgorithmException, InvalidDocumentException {
        // no need to check if dsSignatureValue is null, because it was checked in checkDsSignatureValue
        Element dsSignatureValue = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureValue']");
        String dsSignatureValueString = dsSignatureValue.getStringValue();
        byte[] dsSignatureValueBytes = Base64.getDecoder().decode(dsSignatureValueString);

        TimeStampTokenInfo timestampInfo = token.getTimeStampInfo();
        byte[] messageImprintBytes = timestampInfo.getMessageImprintDigest();

        DefaultAlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
        String algoName = nameFinder.getAlgorithmName(timestampInfo.getMessageImprintAlgOID());

        MessageDigest messageDigest = MessageDigest.getInstance(algoName);
        byte[] hashedSignatureValue = messageDigest.digest(dsSignatureValueBytes);

        if (!Arrays.equals(hashedSignatureValue, messageImprintBytes)) {
            throw new InvalidDocumentException("overenie MessageImprint z časovej pečiatky voči podpisu " +
                    "ds:SignatureValue (zahashovany ds:SignatureValue je iny ako MessageImprint)");
        }
    }
}

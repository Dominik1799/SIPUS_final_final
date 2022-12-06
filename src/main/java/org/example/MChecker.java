package org.example;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.apache.xml.security.c14n.Canonicalizer;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class MChecker implements Checker {
    Document document;

    public MChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, InvalidKeySpecException, CertificateException {
        org.apache.xml.security.Init.init();
        // checkDsSignatureValue();
        checkDsManifestReferences();
    }

    private void checkDsSignatureValue() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, CertificateException {
        Element root = this.document.getRootElement();
        Element dsSignatureValue = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureValue']");
        Element dsCertificate = (Element) root.selectSingleNode("//*[name() = 'ds:X509Certificate']");
        Element signatureMethod = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureMethod']");
        Element dsSignedInfo = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo']");
        Element dsCanonicalizationMethod = (Element) root.selectSingleNode("//*[name() = 'ds:CanonicalizationMethod']");

        if (dsSignatureValue == null) {
            throw new InvalidDocumentException("Chýba ds:SignatureValue element");
        }

        if (dsCertificate == null) {
            throw new InvalidDocumentException("Chýba ds:X509Certificate element v ds:KeyInfo");
        }

        if (dsCanonicalizationMethod == null) {
            throw new InvalidDocumentException("Chýba ds:CanonicalizationMethod element v ds:SignedInfo");
        }

        // Attribute dsX509Certificate = dsCertificate.attribute("ds:X509Certificate");

        String certificateData = dsCertificate.getStringValue();

        String canonicalizationAlg = dsCanonicalizationMethod.attribute("Algorithm").getStringValue();

        // kanonikalizacia ds:SignedInfo
        Canonicalizer canon = Canonicalizer.getInstance(canonicalizationAlg);
        byte[] dsSignedInfoBytes = dsSignedInfo.asXML().getBytes(StandardCharsets.UTF_8);
        byte[] objSignedInfoNew = canon.canonicalize(dsSignedInfoBytes);

        // SubjectPublicKeyInfo ski = SubjectPublicKeyInfo.getInstance(fromByteArray(certificateData.getBytes()));
        // SubjectPublicKeyInfo ski = X509CertificateStructure.getInstance(ASN1Object.fromByteArray(certificateData)).SubjectPublicKeyInfo;
        //SubjectPublicKeyInfo ski = SubjectPublicKeyInfo.getInstance(certificateData.getBytes(StandardCharsets.UTF_8));
        //AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(ski);

        System.out.println(signatureMethod.attribute("Algorithm"));

        String algStr = getAlgorithm(signatureMethod.attribute("Algorithm").getValue());

        //find encryption
        String algorithmId = "1.2.840.10040.4.1";
        if ("1.2.840.10040.4.1".equals(algorithmId)) { //dsa
            algStr += "withdsa";
        } else if ("1.2.840.113549.1.1.1".equals(algorithmId)) { //rsa
            algStr += "withrsa";
        } else {
            throw new InvalidDocumentException("verifySign 5: Unknown key algId = ");
        }

        X509Certificate cert;
        Element root2 = this.document.getRootElement();
        Element dsX509Certificate = getElementByParent(root2, "ds:X509Certificate");

        byte[] decoded = Base64.decode(dsX509Certificate.getText().getBytes());
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(dsX509Certificate.getText().getBytes())).parsePublicKey());
        AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(publicKeyInfo);

        byte[] sig = Base64.decode(dsSignatureValue.getStringValue());
        Signature signer = Signature.getInstance(algStr);
        signer.initVerify((PublicKey) publicKey);
        signer.update(Base64.encode(objSignedInfoNew));
        Boolean res = signer.verify(sig);
        if (!res)
        {
            throw new InvalidDocumentException("verifySign 9: VerifySignature=false: dataB64=" + Base64.encode(objSignedInfoNew));
        }
    }

    private void checkDsManifestReferences() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
        Element root = this.document.getRootElement();
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

            // TODO: dereferencovanie URI -> transformacia podla daneho algoritmu ->
            // TODO: DigestMethod -> DigestValue porovnat s vyslednou hodnotou

            // dereferencovanie URI
            String uri = reference.attribute("URI").getValue().substring(1);
            uri = "Manifest" + uri;
            Element manifestElement = getElementByAttributeValue("ds:Manifest", "Id", uri);

            if (manifestElement == null) {
                continue;
            }

            checkReference(manifestElement);
        }
    }

    private void checkReference(Element reference) throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
        Element dsTransform = getElementByParent(reference, "ds:Transform");
        String transformAlg = dsTransform.attribute("Algorithm").getValue();

        byte[] transformedData = new byte[0];
        byte[] referenceBytes = reference.asXML().getBytes(StandardCharsets.UTF_8);

        // ak je transformacny algoritmus kanonikalizacia
        if (transformAlg.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {
            Canonicalizer canon = Canonicalizer.getInstance(transformAlg);
            transformedData = canon.canonicalize(referenceBytes);
        }
        // ak referencovaný objekt obsahuje len element s base64 kódovanými dátami
        else if (transformAlg.equals("http://www.w3.org/2000/09/xmldsig#base64")) {
            Canonicalizer canon = Canonicalizer.getInstance(transformAlg);
            transformedData = canon.canonicalize(referenceBytes);
        }

        String algoType = getElementByParent(reference, "ds:DigestMethod").attribute("Algorithm").getValue();

        String myDigestValue = "";

        if (algoType.equals("http://www.w3.org/2001/04/xmlenc#sha1")) {
            myDigestValue = Base64.toBase64String(DigestUtils.sha1(transformedData));
        }
        else if (algoType.equals("http://www.w3.org/2001/04/xmlenc#sha256")) {
            myDigestValue = Base64.toBase64String(DigestUtils.sha256(transformedData));
        }
        else if (algoType.equals("http://www.w3.org/2001/04/xmldsig-more#sha384")) {
            myDigestValue = Base64.toBase64String(DigestUtils.sha384(transformedData));
        }
        else if (algoType.equals("http://www.w3.org/2001/04/xmlenc#sha512")) {
            myDigestValue = Base64.toBase64String(DigestUtils.sha512(transformedData));
        }

        String dsDigestValue = getElementByParent(reference, "ds:DigestValue").getStringValue();

        System.out.println("myDigestValue = " + myDigestValue);
        System.out.println("dsDigestValue = " + dsDigestValue);

/*        if (!myDigestValue.equals(dsDigestValue)) {
            throw new InvalidDocumentException("ds:DigestValue má nesprávnu hodnotu.");
        }*/
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

    private Element getElementByParent(Element parent, String elemName) throws InvalidDocumentException {
        Element element = (Element) parent.selectSingleNode("//*[name() = '" + elemName + "']");
        if (element == null) {
            throw new InvalidDocumentException("Chýba " + elemName + " element");
        }
        return element;
    }

    private String getAlgorithm(String algType) {
        switch (algType)
        {
            case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                return "sha1";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                return "sha256";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                return "sha384";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                return "sha512";
        }
        return "";
    }
}

package org.example;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Attr;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import static org.bouncycastle.asn1.ASN1Primitive.fromByteArray;

public class MChecker implements Checker {
    Document document;

    public MChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, InvalidKeySpecException {
        org.apache.xml.security.Init.init();
        checkDsSignatureValue();
        //checkDsManifestReferences();
    }

    private void checkDsSignatureValue() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException {
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
        byte[] aa = dsSignedInfo.asXML().getBytes(StandardCharsets.UTF_8);
        byte[] objSignedInfoNew = canon.canonicalize(aa);

        // SubjectPublicKeyInfo ski = SubjectPublicKeyInfo.getInstance(fromByteArray(certificateData.getBytes()));
        // SubjectPublicKeyInfo ski = X509CertificateStructure.getInstance(ASN1Object.fromByteArray(certificateData)).SubjectPublicKeyInfo;
        //SubjectPublicKeyInfo ski = SubjectPublicKeyInfo.getInstance(certificateData.getBytes(StandardCharsets.UTF_8));
        //AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(ski);

        String algStr = ""; //signature alg

        System.out.println(signatureMethod.attribute("Algorithm"));

        //find digest
        switch (signatureMethod.attribute("Algorithm").getValue())
        {
            case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                algStr = "sha1";
                break;
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                algStr = "sha256";
                break;
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                algStr = "sha384";
                break;
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                algStr = "sha512";
                break;
        }

        //find encryption
        String algorithmId = "1.2.840.10040.4.1";
        if ("1.2.840.10040.4.1".equals(algorithmId)) { //dsa
            algStr += "withdsa";
        } else if ("1.2.840.113549.1.1.1".equals(algorithmId)) { //rsa
            algStr += "withrsa";
        } else {
            throw new InvalidDocumentException("verifySign 5: Unknown key algId = ");
        }

        // PublicKey publicKey = KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(certificateData.getEncoded()));

        byte[] keyBytes = Base64.decode(certificateData.getBytes(StandardCharsets.UTF_8));
        ASN1Sequence ASN1 = ASN1Sequence.getInstance(keyBytes);
        X509CertificateStructure x509 = X509CertificateStructure.getInstance(keyBytes);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(x509);
        AsymmetricKeyParameter pk = PublicKeyFactory.createKey(publicKeyInfo);

        byte[] sig = Base64.decode(dsSignatureValue.getStringValue());
        Signature signer = Signature.getInstance(algStr);
        signer.initVerify((PublicKey) pk);
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

            checkDsDigestValue(reference);
        }
    }

    private void checkDsDigestValue(Element reference) throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
        Element dsTransform = (Element) reference.selectSingleNode("ds:Transforms/ds:Transform");
        Attribute referenceURI = reference.attribute("URI");

        if (dsTransform == null) {
            throw new InvalidDocumentException("Chýba hodnota ds:Transform");
        }

        if (referenceURI == null) {
            throw new InvalidDocumentException("Chýba URI hodnota v ds:Manifest referencii");
        }

        String transformAlg = dsTransform.attribute("Algorithm").getValue();
        byte[] transformedData = Base64.decode("Object201403250803212VerificationObject");

/*        // ak je transformacny algoritmus kanonikalizacia
        if (transformAlg.equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")) {
            Canonicalizer canon = Canonicalizer.getInstance(transformAlg);
            transformedData = canon.canonicalize(Base64.decode(referenceURI.getValue()));
        }
        // ak referencovaný objekt obsahuje len element s base64 kódovanými dátami
        else if (transformAlg.equals("http://www.w3.org/2000/09/xmldsig#base64")) {
            Canonicalizer canon = Canonicalizer.getInstance(transformAlg);
            transformedData = canon.canonicalize(Base64.decode(referenceURI.getValue()));
        }*/

        Element dsDigestMethod = (Element) reference.selectSingleNode("ds:DigestMethod");
        String digestAlg = dsDigestMethod.attribute("Algorithm").getValue();

        // myDigestValue = digestAlg -> transformedData

        String myDigestValue = "";

        if (digestAlg.equals("http://www.w3.org/2001/04/xmlenc#sha256")) {
            myDigestValue = DigestUtils.sha256Hex(transformedData);
        }

        Element dsDigestValue = (Element) reference.selectSingleNode("ds:DigestValue");

        System.out.println("myDigestValue = " + myDigestValue);
        System.out.println("dsDigestValue = " + dsDigestValue.getStringValue());


    }
}

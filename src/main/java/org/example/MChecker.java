package org.example;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
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
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

import static org.bouncycastle.asn1.ASN1Primitive.fromByteArray;

public class MChecker implements Checker {
    Document document;

    public MChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        // checkDsSignatureValue();
        checkDsManifestReferences();
    }

    private byte[] canonicalize(Element signedInfoN, String alg) {
        byte[] bytes = Base64.decode("");
        return bytes;
    }

    private void checkDsSignatureValue() throws InvalidDocumentException, InvalidCanonicalizerException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
        Element root = this.document.getRootElement();
        Element dsSignatureValue = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureValue']");
        Element dsCertificate = (Element) root.selectSingleNode("//*[name() = 'ds:X509Certificate']");
        Element signatureMethod = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo/ds:SignatureMethod']");
        Element dsSignedInfo = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo']");
        Element dsCanonicalizationMethod = (Element) root.selectSingleNode("//*[name() = 'ds:CanonicalizationMethod']");
        // byte[] objSignedInfoOld = this.canonicalize(signedInfoN, dsCanonicalizationMethod.getStringValue());

        String ERROR_MSG = "";

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
        System.out.println(dsCertificate);

        // kanonikalizacia ds:SignedInfo
        Canonicalizer canon = Canonicalizer.getInstance(dsCanonicalizationMethod.getStringValue());
        byte[] objSignedInfoNew = canon.canonicalize(Base64.decode(dsSignedInfo.getStringValue()));

        //byte[] objSignedInfoNew = this.canonicalize(signedInfoN, dsCanonicalizationMethod.getStringValue());

        try
        {
            SubjectPublicKeyInfo ski = X509CertificateStructure.getInstance(fromByteArray(certificateData.getBytes(StandardCharsets.UTF_8))).getSubjectPublicKeyInfo();
            AsymmetricKeyParameter pk = PublicKeyFactory.createKey(ski);

            String algStr = ""; //signature alg

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
            AlgorithmIdentifier algorithmId = ski.getAlgorithmId();
            if ("1.2.840.10040.4.1".equals(algorithmId)) { //dsa
                algStr += "withdsa";
            } else if ("1.2.840.113549.1.1.1".equals(algorithmId)) { //rsa
                algStr += "withrsa";
            } else {
                ERROR_MSG = "verifySign 5: Unknown key algId = " + ski.getAlgorithmId();
                throw new InvalidDocumentException(ERROR_MSG);
            }

            byte[] sig = Base64.decode(dsSignatureValue.getStringValue());
            ERROR_MSG = "verifySign 8: Creating signer: " + algStr;
            Signature signer = Signature.getInstance("SHA1withDSA");
            signer.initVerify((PublicKey) pk);
            signer.update(Byte.parseByte(certificateData));
            Boolean res = signer.verify(sig);
            if (!res)
            {
                ERROR_MSG = "verifySign 9: VerifySignature=false: dataB64=" + Base64.encode(objSignedInfoNew);
            }

            throw new InvalidDocumentException(ERROR_MSG);

        }
        catch (Exception ex)
        {
            ERROR_MSG = "verifySign 10: " + ex;
            throw new InvalidDocumentException(ERROR_MSG);
        }
    }

    private void checkDsManifestReferences() throws InvalidDocumentException {
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

            checkDsDigestValue(reference);
        }
    }

    private void checkDsDigestValue(Element reference) throws InvalidDocumentException {
        Element dsDigestValue = (Element) reference.selectSingleNode("ds:DigestValue");
        Attribute referenceURI = reference.attribute("URI");

        if (dsDigestValue == null) {
            throw new InvalidDocumentException("Chýba hodnota ds:DigestValue");
        }

        if (referenceURI == null) {
            throw new InvalidDocumentException("Chýba URI hodnota v ds:Manifest referencii");
        }

        String decodedDigestValue = dsDigestValue.getStringValue();
        System.out.println(decodedDigestValue);
        System.out.println(referenceURI.getValue());
    }
}

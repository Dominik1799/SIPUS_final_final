package org.example;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import org.dom4j.Document;
import org.dom4j.Element;
import java.security.PublicKey;
import java.security.Signature;

import java.nio.charset.StandardCharsets;

import static org.bouncycastle.asn1.ASN1Primitive.fromByteArray;

public class MChecker implements Checker {
    Document document;

    public MChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {
        checkDsSignatureValue();
    }

    private byte[] canonicalize(Element signedInfoN, String alg) {
        byte[] bytes = Base64.decode("");
        return bytes;
    }

    private void checkDsSignatureValue() throws InvalidDocumentException {
        Element root = this.document.getRootElement();
        Element dsSignatureValue = (Element) root.selectSingleNode("//*[name() = 'ds:SignatureValue']");
        String certificateData = root.selectSingleNode("//*[name() = 'ds:KeyInfo/ds:X509Data/ds:X509Certificate']").getStringValue();
        Element signatureMethod = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo/ds:SignatureMethod']");
        Element signedInfoN = (Element) root.selectSingleNode("//*[name() = 'ds:SignedInfo']");
        String signedInfoTransformAlg = root.selectSingleNode("//*[name() = 'ds:SignedInfo/ds:CanonicalizationMethod']").getStringValue();
        byte[] objSignedInfoOld = this.canonicalize(signedInfoN, signedInfoTransformAlg);
        byte[] objSignedInfoNew = this.canonicalize(signedInfoN, signedInfoTransformAlg);


        String ERROR_MSG = "";

        if (dsSignatureValue == null) {
            throw new InvalidDocumentException("Chýba ds:SignatureValue element");
        }

        if (certificateData == null) {
            throw new InvalidDocumentException("Chýba ds:X509Certificate element v ds:KeyInfo");
        }

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
}

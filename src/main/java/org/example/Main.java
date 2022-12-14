package org.example;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.tsp.TSPException;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

//kniznica: https://dom4j.github.io/
//priklady: https://www.tutorialspoint.com/java_xml/java_dom4j_parse_document.htm
public class Main {
    private final static String XML_FILE = "priklady/03XadesT.xml";
    public static void main(String[] args) {
        try {
            // init
            FileReader fileReader = new FileReader(XML_FILE, StandardCharsets.UTF_8);
            SAXReader reader = new SAXReader();
            Document document = reader.read(fileReader);
            Checker dChecker = new DChecker(document);
            Checker aChecker = new AChecker(document);
            Checker jChecker = new JChecker(document);
            Checker mChecker = new MChecker(document);

            // start checking
            // dChecker.startCheck();
            // aChecker.startCheck();

            // valid: 1, 2, 3, 4, 7, 8, 9, 11, 12
            // not valid: 5, 6, 10
            // jChecker.startCheck();
            mChecker.startCheck();

            // if we get here, no exceptions occured == document is valid
            System.out.println("Dokument je platny");
        } catch (DocumentException e) {
            System.err.println("Neplatny XML dokument. Zla struktura");
        } catch (InvalidDocumentException e) {
            System.err.println("Dokument nie je validny. Dovod: ");
            System.err.println(e.getMessage());
        } catch (IOException | NoSuchAlgorithmException | TSPException | InvalidCanonicalizerException | CanonicalizationException | ParserConfigurationException | SAXException e) {
            System.err.println("Nastal problem s pri vyuziti externej kniznice.");
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }


    }
}
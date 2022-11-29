package org.example;
import org.dom4j.*;
import org.dom4j.io.SAXReader;

import java.io.File;

//kniznica: https://dom4j.github.io/
//priklady: https://www.tutorialspoint.com/java_xml/java_dom4j_parse_document.htm
public class Main {
    private final static String XML_FILE = "priklady/ez_dokument.xml";
    public static void main(String[] args) throws DocumentException {
        File xmlFile = new File(XML_FILE);
        SAXReader reader = new SAXReader();
        Document document = reader.read(xmlFile);
        Element root = document.getRootElement();
        System.out.println(root.selectSingleNode("staff").selectSingleNode("bio").getText());
    }
}
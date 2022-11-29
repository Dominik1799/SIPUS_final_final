package org.example;

import org.dom4j.Document;

public class JChecker implements Checker{

    Document document;

    public JChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {

    }
}

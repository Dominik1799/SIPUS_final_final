package org.example;

import org.dom4j.Document;

public class AChecker implements Checker{
    Document document;

    public AChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {

    }
}

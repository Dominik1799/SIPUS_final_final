package org.example;

import org.dom4j.Document;

public class MChecker implements Checker {
    Document document;

    public MChecker(Document document) {
        this.document = document;
    }

    @Override
    public void startCheck() throws InvalidDocumentException {

    }
}

package org.example;

public class InvalidDocumentException extends Exception {
    public InvalidDocumentException(String errorMessage) {
        super(errorMessage);
    }
}

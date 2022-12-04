package org.example;

import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public interface Checker {
    void startCheck() throws InvalidDocumentException, IOException, NoSuchAlgorithmException, TSPException;
}

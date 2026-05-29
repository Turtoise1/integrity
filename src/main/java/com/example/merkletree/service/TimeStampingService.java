package com.example.merkletree.service;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.stereotype.Service;

@Service
public class TimeStampingService {

    /**
     * Taken from
     * https://www.javatips.net/api/jsign-master/jsign-core/src/main/java/net/jsign/timestamp/RFC3161Timestamper.java
     *
     * Copyright 2014 Florent Daigniere
     *
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at
     *
     * http://www.apache.org/licenses/LICENSE-2.0
     */
    public TimeStampToken requestTimeStamp(TimeStampRequest request) {
        URL tsaurl;
        try {
            tsaurl = URI.create("https://zeitstempel.dfn.de/").toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("Invalid URL", e);
        }

        HttpURLConnection conn;
        try {
            byte encodedRequest[] = request.getEncoded();

            conn = (HttpURLConnection) tsaurl.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-type", "application/timestamp-query");
            conn.setRequestProperty("Content-length", String.valueOf(encodedRequest.length));
            conn.setRequestProperty("Accept", "application/timestamp-reply");
            conn.setRequestProperty("User-Agent", "Transport");

            conn.getOutputStream().write(encodedRequest);
            conn.getOutputStream().flush();

            if (conn.getResponseCode() >= 400) {
                throw new RuntimeException(
                        "Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode()
                                + " - " + conn.getResponseMessage());
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not open a http connection for timestamping due: " + e.getMessage());
        }

        try (ASN1InputStream inputStream = new ASN1InputStream(conn.getInputStream())) {

            TimeStampResp resp = TimeStampResp.getInstance(inputStream.readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(request);
            if (response.getStatus() != 0) {
                throw new IOException("Unable to complete the timestamping due to an invalid response ("
                        + response.getStatusString() + ")");
            }

            return response.getTimeStampToken();

        } catch (Exception e) {
            throw new RuntimeException("Unable to complete the timestamping", e);
        }
    }
}

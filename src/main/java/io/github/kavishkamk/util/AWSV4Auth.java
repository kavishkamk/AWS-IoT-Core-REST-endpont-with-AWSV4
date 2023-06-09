package io.github.kavishkamk.util;

import io.quarkus.logging.Log;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @reference <a href="https://www.javaquery.com/2016/01/aws-version-4-signing-process-complete.html">...</a>
 *       this code was modified for compatibility of the required process
 */
public class AWSV4Auth {

    private AWSV4Auth() {
    }

    public static class Builder {

        private final String accessKeyID;
        private final String secretAccessKey;
        private String regionName;
        private String serviceName;
        private String httpMethodName;
        private String canonicalURI;
        private Map<String, String> queryParameters;
        private Map<String, String> awsHeaders;
        private String payload;
        private boolean debug = false;

        public Builder(String accessKeyID, String secretAccessKey) {
            this.accessKeyID = accessKeyID;
            this.secretAccessKey = secretAccessKey;
        }

        public Builder regionName(String regionName) {
            this.regionName = regionName;
            return this;
        }

        public Builder serviceName(String serviceName) {
            this.serviceName = serviceName;
            return this;
        }

        public Builder httpMethodName(String httpMethodName) {
            this.httpMethodName = httpMethodName;
            return this;
        }

        public Builder canonicalURI(String canonicalURI) {
            this.canonicalURI = canonicalURI;
            return this;
        }

        public Builder queryParameters(TreeMap<String, String> queryParameters) {
            this.queryParameters = queryParameters;
            return this;
        }

        public Builder awsHeaders(TreeMap<String, String> awsHeaders) {
            this.awsHeaders = awsHeaders;
            return this;
        }

        public Builder payload(String payload) {
            this.payload = payload;
            return this;
        }

        public Builder debug() {
            this.debug = true;
            return this;
        }

        public AWSV4Auth build() {
            return new AWSV4Auth(this);
        }
    }

    private String accessKeyID;
    private String secretAccessKey;
    private String regionName;
    private String serviceName;
    private String httpMethodName;
    private String canonicalURI;
    private Map<String, String> queryParameters;
    private Map<String, String> awsHeaders;
    private String payload;
    private boolean debug = false;

    /* Other variables */
    private static final String HMAC_ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String AWS_4_REQUEST = "aws4_request";
    private String strSignedHeader;
    private String xAmzDate;
    private String currentDate;

    private AWSV4Auth(Builder builder) {
        accessKeyID = builder.accessKeyID;
        secretAccessKey = builder.secretAccessKey;
        regionName = builder.regionName;
        serviceName = builder.serviceName;
        httpMethodName = builder.httpMethodName;
        canonicalURI = builder.canonicalURI;
        queryParameters = builder.queryParameters;
        awsHeaders = builder.awsHeaders;
        payload = builder.payload;
        debug = builder.debug;

        /* Get current timestamp value.(UTC) */
        xAmzDate = getTimeStamp();
        currentDate = getDate();
    }

    /**
     * Task 1: Create a Canonical Request for Signature Version 4.
     *
     */
    private String prepareCanonicalRequest() {
        StringBuilder canonicalURL = new StringBuilder();

        /* Step 1.1 Start with the HTTP request method (GET, PUT, POST, etc.), followed by a newline character. */
        canonicalURL.append(httpMethodName).append("\n");

        /* Step 1.2 Add the canonical URI parameter, followed by a newline character. */
        canonicalURI = canonicalURI == null || canonicalURI.trim().isEmpty() ? "/" : canonicalURI;
        canonicalURL.append(canonicalURI).append("\n");

        /* Step 1.3 Add the canonical query string, followed by a newline character. */
        StringBuilder queryString = new StringBuilder();
        if (queryParameters != null && !queryParameters.isEmpty()) {
            for (Map.Entry<String, String> entrySet : queryParameters.entrySet()) {
                String key = entrySet.getKey();
                String value = entrySet.getValue();
                queryString.append(key).append("=").append(encodeParameter(value)).append("&");
            }

            /* @co-author https://github.com/dotkebi @git #1 @date 16th March, 2017 */
            queryString.deleteCharAt(queryString.lastIndexOf("&"));

            queryString.append("\n");
        } else {
            queryString.append("\n");
        }
        canonicalURL.append(queryString);

        /* Step 1.4 Add the canonical headers, followed by a newline character. */
        StringBuilder signedHeaders = new StringBuilder();
        if (awsHeaders != null && !awsHeaders.isEmpty()) {
            for (Map.Entry<String, String> entrySet : awsHeaders.entrySet()) {
                String key = entrySet.getKey();
                String value = entrySet.getValue();
                signedHeaders.append(key).append(";");
                canonicalURL.append(key).append(":").append(value).append("\n");
            }

            /* Note: Each individual header is followed by a newline character, meaning the complete list ends with a newline character. */
            canonicalURL.append("\n");
        } else {
            canonicalURL.append("\n");
        }

        /* Step 1.5 Add the signed headers, followed by a newline character. */
        strSignedHeader = signedHeaders.substring(0, signedHeaders.length() - 1); // Remove last ";"
        canonicalURL.append(strSignedHeader).append("\n");

        /* Step 1.6 Use a hash (digest) function like SHA256 to create a hashed value from the payload in the body of the HTTP or HTTPS. */
        payload = payload == null ? "" : payload;
        canonicalURL.append(generateHex(payload));

        if (debug) {
            Log.error("##Canonical Request:\n" + canonicalURL);
        }

        return canonicalURL.toString();
    }

    /**
     * Task 2: Create a String to Sign for Signature Version 4.
     */
    private String prepareStringToSign(String canonicalURL) {
        String stringToSign;

        /* Step 2.1 Start with the algorithm designation, followed by a newline character. */
        stringToSign = HMAC_ALGORITHM + "\n";

        /* Step 2.2 Append the request date value, followed by a newline character. */
        stringToSign += xAmzDate + "\n";

        /* Step 2.3 Append the credential scope value, followed by a newline character. */
        stringToSign += currentDate + "/" + regionName + "/" + serviceName + "/" + AWS_4_REQUEST + "\n";

        /* Step 2.4 Append the hash of the canonical request that you created in Task 1: Create a Canonical Request for Signature Version 4. */
        stringToSign += generateHex(canonicalURL);

        if (debug) {
            Log.error("##String to sign:\n" + stringToSign);
        }

        return stringToSign;
    }

    /**
     * Task 3: Calculate the AWS Signature Version 4.
     *
     */
    private String calculateSignature(String stringToSign) {
        try {
            /* Step 3.1 Derive your signing key */
            byte[] signatureKey = getSignatureKey(secretAccessKey, currentDate, regionName, serviceName);

            /* Step 3.2 Calculate the signature. */
            byte[] signature = getHmacSHA256(signatureKey, stringToSign);

            /* Step 3.2.1 Encode signature (byte[]) to Hex */
            return bytesToHex(signature);
        } catch (Exception ex) {
            Log.error(ex.getMessage());
        }
        return null;
    }

    /**
     * Task 4: Add the Signing Information to the Request. We'll return Map of
     * all headers put these headers in your request.
     *
     */
    public Map<String, String> getHeaders() {
        awsHeaders.put("x-amz-date", xAmzDate);

        /* Execute Task 1: Create a Canonical Request for Signature Version 4. */
        String canonicalURL = prepareCanonicalRequest();

        /* Execute Task 2: Create a String to Sign for Signature Version 4. */
        String stringToSign = prepareStringToSign(canonicalURL);

        /* Execute Task 3: Calculate the AWS Signature Version 4. */
        String signature = calculateSignature(stringToSign);

        if (signature != null) {
            Map<String, String> header = new HashMap<>(0);
            header.put("x-amz-date", xAmzDate);
            header.put("authorization", buildAuthorizationString(signature));

            if (debug) {
                Log.error("##Signature:\n" + signature);
                Log.error("##Header:");
                for (Map.Entry<String, String> entrySet : header.entrySet()) {
                    Log.error(entrySet.getKey() + " = " + entrySet.getValue());
                }
                Log.error("================================");
            }
            return header;
        } else {
            if (debug) {
                Log.error("##Signature: null\n");
            }
            return new HashMap<>();
        }
    }

    /**
     * Build string for Authorization header.
     *
     */
    private String buildAuthorizationString(String strSignature) {
        return HMAC_ALGORITHM + " "
                + "Credential=" + accessKeyID + "/" + getDate() + "/" + regionName + "/" + serviceName + "/" + AWS_4_REQUEST + ","
                + "SignedHeaders=" + strSignedHeader + ","
                + "Signature=" + strSignature;
    }

    /**
     * Generate Hex code of String.
     */
    private String generateHex(String data) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] digest = messageDigest.digest();
            return String.format("%064x", new java.math.BigInteger(1, digest));
        } catch (NoSuchAlgorithmException e) {
            Log.error(e.getMessage());
        }
        return null;
    }

    /**
     * Apply HmacSHA256 on data using given key.
     * @reference:
     * <a href="http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-java">...</a>
     */
    private byte[] getHmacSHA256(byte[] key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate AWS signature key.
     * @reference
     * <a href="http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-java">...</a>
     */
    private byte[] getSignatureKey(String key, String date, String regionName, String serviceName) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = getHmacSHA256(kSecret, date);
        byte[] kRegion = getHmacSHA256(kDate, regionName);
        byte[] kService = getHmacSHA256(kRegion, serviceName);
        return getHmacSHA256(kService, AWS_4_REQUEST);
    }

    protected static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Convert byte array to Hex
     *
     */
    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }

    /**
     * Get timestamp. yyyyMMdd'T'HHmmss'Z'
     *
     */
    private String getTimeStamp() {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));//server timezone
        return dateFormat.format(new Date());
    }

    /**
     * Get date. yyyyMMdd
     *
     */
    private String getDate() {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));//server timezone
        return dateFormat.format(new Date());
    }

    /**
     * @co-author <a href="https://github.com/dotkebi">...</a>
     * @date 16th March 2017
     * @git #1
     */
    private String encodeParameter(String param) {
        try {
            return URLEncoder.encode(param, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return URLEncoder.encode(param);
        }
    }
}

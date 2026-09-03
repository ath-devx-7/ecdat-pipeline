// Legacy settlement utilities — ECDAT demo target D (SPEC.md §14).
//
// The Java half of the code-scan target. It exists for three reasons:
//
//   1. Semgrep rules for `MessageDigest.getInstance("MD5")` are a different
//      shape from the Python `hashlib.md5` rules, and both have to ship.
//   2. The same weakness appearing in two languages must collapse to one
//      algorithm identity in the normalizer (§8), not two dashboard rows.
//   3. It carries a java.security file, which is a config-layer declaration
//      about crypto from a source that is neither a TLS server nor a cert.
//
// Lines carrying an `ECDAT-EXPECT:` marker are the ones a collector must
// report. See demo/README.md for the convention.

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class HashDemo {

    // ECDAT-EXPECT: hardcoded-key
    // Key material as a string literal, which is worse in Java than it looks:
    // String is interned, so it stays in the constant pool and in any heap dump.
    private static final String SETTLEMENT_DES_KEY = "8bytekey";

    /** MD5 over a settlement record. Broken for anything trust-bearing. */
    static String recordFingerprint(String record) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");  // ECDAT-EXPECT: weak-hash-md5
        return toHex(md5.digest(record.getBytes("UTF-8")));
    }

    /** SHA-1 over a statement blob. */
    static String statementChecksum(byte[] blob) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");  // ECDAT-EXPECT: weak-hash-sha1
        return toHex(sha1.digest(blob));
    }

    /**
     * 1024-bit RSA for signing outbound files: below the SP 800-131A Rev.2
     * floor, so `broken_now` rather than `quantum_vulnerable`, and a signature
     * primitive, so Mosca's inequality does not apply to it (§12).
     */
    static KeyPairGenerator signingKeyGenerator() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);  // ECDAT-EXPECT: rsa-weak-key
        return kpg;
    }

    /** Single-DES in ECB mode — a 56-bit key and a mode that leaks structure. */
    static byte[] encryptPartnerRecord(byte[] plaintext) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SETTLEMENT_DES_KEY.getBytes("UTF-8"), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");  // ECDAT-EXPECT: weak-cipher-des
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        // Loops so the container stays up and remains scannable as an image.
        while (true) {
            System.out.println("fingerprint : " + recordFingerprint("demo-settlement-0001"));
            System.out.println("checksum    : " + statementChecksum("demo statement".getBytes("UTF-8")));
            System.out.println("signing key : RSA-" + signingKeyGenerator().getClass().getSimpleName());
            System.out.println("des blob    : " + encryptPartnerRecord("demo record".getBytes("UTF-8")).length + " bytes");
            System.out.flush();
            Thread.sleep(60_000);
        }
    }
}

package ee.mrtn.yubiunwrap;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    static final int YHW_HEADER_LEN = 59;

    public static void main(String[] args) throws Exception {

        if (args.length < 3) {
            System.err.println("Usage: java -jar yubihsm-unwrap.jar <pubkey> <wrapped> <wrapkey> [output]");
            System.exit(1);
        }

        // Get arguments
        PublicKey pub = pem2PublicKey(Files.newInputStream(Paths.get(args[0])));
        byte[] blob = Base64.getDecoder().decode(Files.readString(Paths.get(args[1])).trim());
        byte[] key = Hex.decode(Files.readString(Paths.get(args[2])).trim());

        Security.addProvider(new BouncyCastleProvider());

        // Decrypt the blob with wrapkey
        byte[] unwrap = unwrap(blob, key);

        // Extract the private key from blob
        RSAPrivateKey priv = blob2rsa(unwrap, pub);

        // As the optional passphrase
        char[] pass = System.console().readPassword("Key export password (optional): ");

        // convert private key to pem
        StringWriter privpem = new StringWriter();
        try (PemWriter pemWriter = new JcaPEMWriter(privpem)) {
            OutputEncryptor protection = pass.length == 0 ? null : new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_128_CBC).setPassword(pass).build();
            pemWriter.writeObject(new JcaPKCS8Generator(priv, protection));
        }

        if (args.length == 4) {
            Files.writeString(Paths.get(args[3]), privpem.toString());
        } else {
            System.out.println(privpem);
        }
    }

    // Basic unwrap with CCM mode of yubihsm
    static byte[] unwrap(byte[] payload, byte[] key) throws GeneralSecurityException {
        Cipher aesccm = Cipher.getInstance("AES/CCM/NoPadding");

        byte[] iv = Arrays.copyOf(payload, 13);
        byte[] tag = Arrays.copyOfRange(payload, payload.length - 16, payload.length);
        byte[] cipherTextWithTag = Arrays.copyOfRange(payload, 13, payload.length);

        aesccm.init(Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));

        return aesccm.doFinal(cipherTextWithTag);
    }


    static RSAPrivateKey blob2rsa(byte[] blob, PublicKey pubkey) throws GeneralSecurityException, IOException {
        if (!(pubkey instanceof RSAPublicKey))
            throw new IllegalArgumentException("Only RSA keys supported");

        RSAPublicKey rsapub = (RSAPublicKey) pubkey;
        // Extract components from blob
        BigInteger e = rsapub.getPublicExponent();

        // Lengths of components
        int len = rsapub.getModulus().bitLength() / 8;
        int complen = len / 2;

        // Remove header - we don't need anything from there.
        byte[] header = Arrays.copyOf(blob, YHW_HEADER_LEN);
        byte[] payload = Arrays.copyOfRange(blob, YHW_HEADER_LEN, blob.length);

        int offset = 0;
        byte[] prime1b = Arrays.copyOfRange(payload, offset, offset + complen);
        offset += complen;
        BigInteger p = new BigInteger(1, prime1b);

        byte[] prime2b = Arrays.copyOfRange(payload, offset, offset + complen);
        offset += complen;
        BigInteger q = new BigInteger(1, prime2b);

        byte[] exp1b = Arrays.copyOfRange(payload, offset, offset + complen);
        offset += complen;
        BigInteger dp = new BigInteger(1, exp1b);

        byte[] exp2b = Arrays.copyOfRange(payload, offset, offset + complen);
        offset += complen;
        BigInteger dq = new BigInteger(1, exp2b);

        byte[] coefb = Arrays.copyOfRange(payload, offset, offset + complen);
        offset += complen;
        BigInteger c = new BigInteger(1, coefb);

        byte[] modulusb = Arrays.copyOfRange(payload, offset, offset + len);
        offset += len;
        BigInteger n = new BigInteger(1, modulusb);

        byte[] remaining = Arrays.copyOfRange(payload, offset, payload.length);
        if (remaining.length != 0)
            throw new IllegalArgumentException("Remaining bytes in input");

        // In theory we can omit public key and assume 0x10001 to construct everything, but let's be strict
        if (!n.equals(rsapub.getModulus())) {
            throw new IllegalArgumentException("Modulus of public key and private key don't match");
        }

        // Calculate private exponent from CRT components, d = e^-1 mod (p-1)(q-1)
        BigInteger d = n;
        d = d.subtract(p);
        d = d.subtract(q);
        d = d.add(BigInteger.ONE);
        d = d.modInverse(e);

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, c);

        // Create private key
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        RSAPrivateCrtKey privkey = (RSAPrivateCrtKey) factory.generatePrivate(spec);

        // Verify keypair

        // Generate random data
        byte[] random = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(random);

        // Encrypt with public, decrypt with private
        Cipher pkcs1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        pkcs1.init(Cipher.ENCRYPT_MODE, pubkey);
        byte[] cryptogram = pkcs1.doFinal(random);

        pkcs1.init(Cipher.DECRYPT_MODE, privkey);
        byte[] decrypted = pkcs1.doFinal(cryptogram);

        // Check that roundtrip matches
        if (!Arrays.equals(random, decrypted)) {
            throw new IllegalArgumentException("Public key and private key mismatch!");
        }
        return privkey;
    }


    // Get a public key from a PEM file, either public key or keypair
    public static PublicKey pem2PublicKey(InputStream in) throws IOException {
        try (PEMParser pem = new PEMParser(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            Object ohh = pem.readObject();
            if (ohh instanceof PEMKeyPair kp) {
                return new JcaPEMKeyConverter().getKeyPair(kp).getPublic();
            } else if (ohh instanceof SubjectPublicKeyInfo) {
                return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) ohh);
            } else if (ohh instanceof X509CertificateHolder certHolder) {
                try {
                    return new JcaX509CertificateConverter().getCertificate(certHolder).getPublicKey();
                } catch (CertificateException ce) {
                    throw new IllegalArgumentException("Can not read PEM: " + ce.getMessage());
                }
            } else throw new IllegalArgumentException("Not supported: " + ohh.getClass().getSimpleName());
        }
    }

}
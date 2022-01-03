import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyGen {

    private static KeyPair generatedKeyPair = null;
    private static KeyGen instance = null;

    private KeyGen() {

        // Adding the additional algorithms for optimal security
        Security.addProvider(new BouncyCastleProvider());
        generateKeyPair();

    }

    private void generateKeyPair() {

        try {

            KeyPairGenerator eccKeyPairGenerator = KeyPairGenerator.getInstance("EC");
            eccKeyPairGenerator.initialize(new ECGenParameterSpec("brainpoolP384r1")); // ECC-384 (very high security)
            generatedKeyPair = eccKeyPairGenerator.generateKeyPair();

            // Validating whether Public & Private Key work together with a test digital signature
            if (validateKeyPair()) System.out.println("KeyPair Generated & Validated w/ Signature");

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    private boolean validateKeyPair() {

        try {

            Signature privateKeySignature = Signature.getInstance("SHA512withECDSA");
            Signature publicKeySignature = Signature.getInstance("SHA512withECDSA");

            byte[] plainByteText = new String("Heute sind alle Schnitzel schmackhaft").getBytes();

            privateKeySignature.initSign(generatedKeyPair.getPrivate());
            privateKeySignature.update(plainByteText);

            byte[] signByteText = privateKeySignature.sign();

            publicKeySignature.initVerify(generatedKeyPair.getPublic());
            publicKeySignature.update(plainByteText);

            return publicKeySignature.verify(signByteText);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return false;

    }


    public static KeyGen getInstance() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (instance == null) instance = new KeyGen();
        return instance;
    }

    public PublicKey getPublicKey() {
        return generatedKeyPair.getPublic();
    }


    // Returns the encrypted object byte stream
    public byte[] encryptObject(ExampleDTO dto, Cipher cipherAlgorithm) {

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos)) {

            oos.writeObject(dto);
            byte[] byteStream = bos.toByteArray();

            cipherAlgorithm.init(Cipher.ENCRYPT_MODE, generatedKeyPair.getPublic());
            return cipherAlgorithm.doFinal(byteStream);

        } catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return null;

    }

    // Returns the decrypted object
    // AlgorithmParameters contains the IV (Initialization Vector), which needs to be sent from the Client to the Server
    // It is safe to sent it unencrypted as it doesn't contain the key, they are basically just "salts"
    public ExampleDTO decryptObject(byte[] encryptedObjectByteStream, AlgorithmParameters algorithmParameters) {

        try {

            Cipher eciesDecipher = Cipher.getInstance("ECIESwithAES-CBC");
            eciesDecipher.init(Cipher.DECRYPT_MODE, generatedKeyPair.getPrivate(), algorithmParameters);
            byte[] decryptedObjectStream = eciesDecipher.doFinal(encryptedObjectByteStream);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(decryptedObjectStream); ObjectInput ois = new ObjectInputStream(bis)) {
                return ((ExampleDTO) ois.readObject());
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }

        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;

    }

}

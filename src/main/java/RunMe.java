import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class RunMe {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException {
        KeyGen keyGen = KeyGen.getInstance();

        ExampleDTO dto = new ExampleDTO("bha9465", "PssWrD");

        Cipher cipherEncrypt = Cipher.getInstance("ECIESwithAES-CBC");
        byte[] encryptedByteStream = keyGen.encryptObject(dto, cipherEncrypt);
        ExampleDTO decryptedDTO = keyGen.decryptObject(encryptedByteStream, cipherEncrypt.getParameters());

        System.out.println("Original DTO: " + dto.toString());
        System.out.println("Encrypted DTO: " + new String(encryptedByteStream));
        System.out.println("Decrypted DTO: " + decryptedDTO.toString());

    }


}

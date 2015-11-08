package cryptography;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Week2AesCbcCtrProblem {

    private static final Logger LOGGER = LoggerFactory.getLogger(Week2AesCbcCtrProblem.class);

    private static final int AES_BLOCK_SIZE_BITS = 128;
    private static final int BITS_PER_BYTE = 8;

    public static void main(String[] args) {

        try {
            String cbcKey = "140b41b22a29beb4061bda66b6747e14";
            String cbcCipherText_1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
            String cbcCipherText_2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
            String ctrKey = "36f18357be4dbd77f050515c73fcf9f2";
            String ctrCipherText_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
            String ctrCipherText_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

            LOGGER.info("Check length of CBC key:");
            checkKeyLength(cbcKey);
            LOGGER.info("Check length of CTR key:");
            checkKeyLength(ctrKey);
            
            byte[] decrypted = aesDecrypt(cbcKey, cbcCipherText_1, "AES/CBC/PKCS5Padding");
            LOGGER.info("CBC Plaintext 1 : " + new String(decrypted));

            decrypted = aesDecrypt(cbcKey, cbcCipherText_2, "AES/CBC/PKCS5Padding");
            LOGGER.info("CBC Plaintext 2 : " + new String(decrypted));

            decrypted = aesDecrypt(ctrKey, ctrCipherText_1, "AES/CTR/NoPadding");
            LOGGER.info("CTR Plaintext 1 : " + new String(decrypted));

            decrypted = aesDecrypt(ctrKey, ctrCipherText_2, "AES/CTR/NoPadding");
            LOGGER.info("CTR Plaintext 2 : " + new String(decrypted));

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void checkKeyLength(String hexKey) {
        String toBits = CipherUtils.hexStringToBinaryString(hexKey);

        LOGGER.info("\tHexChars: " + hexKey.length() + " - Bits: " + toBits.length() + " - Bytes: "
                + (toBits.length() / BITS_PER_BYTE));

        int blocks = toBits.length() / AES_BLOCK_SIZE_BITS;
        int remainderBits = toBits.length() % AES_BLOCK_SIZE_BITS;
        int remainderBytes = remainderBits / BITS_PER_BYTE;

        LOGGER.info("\tBlocks: " + blocks + " - Remainder (bits): " + remainderBits + " - Remainder (bytes): "
                + remainderBytes + " - Whole num of bytes ? : " + ((remainderBits % BITS_PER_BYTE) == 0));
    }    
        
    private static byte[] aesDecrypt(String hexKey, String hexCipherText, String cipherType)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        SecretKey aesKey = new SecretKeySpec(CipherUtils.hexStringToByteArray(hexKey), "AES");

        Cipher cipher = Cipher.getInstance(cipherType);

        // Remove IV (first 16 bytes) from front of ciphertext
        byte[] ivPlusCt = CipherUtils.hexStringToByteArray(hexCipherText);
        byte[] iv = Arrays.copyOfRange(ivPlusCt, 0, 16);
        byte[] ct = Arrays.copyOfRange(ivPlusCt, 16, ivPlusCt.length);

        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(ct);
    }
}

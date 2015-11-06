package cryptography;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
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

            String toBits = CipherUtils.hexStringToBinaryString(cbcKey);

            LOGGER.info("\tHexChars: " + cbcKey.length() + " - Bits: " + toBits.length() + " - Bytes: "
                    + (toBits.length() / BITS_PER_BYTE));

            int blocks = toBits.length() / AES_BLOCK_SIZE_BITS;
            int remainderBits = toBits.length() % AES_BLOCK_SIZE_BITS;
            int remainderBytes = remainderBits / BITS_PER_BYTE;

            LOGGER.info("\tBlocks: " + blocks + " - Remainder (bits): " + remainderBits + " - Remainder (bytes): "
                    + remainderBytes + " - Whole num of bytes ? : " + ((remainderBits % BITS_PER_BYTE) == 0));

            SecretKey aesKey = new SecretKeySpec(CipherUtils.hexStringToByteArray(cbcKey), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Remove IV (first 16 bytes) from front of ciphertext
            byte[] ivPlusCt_1 = CipherUtils.hexStringToByteArray(cbcCipherText_1);
            byte[] iv_1 = Arrays.copyOfRange(ivPlusCt_1, 0, 16);
            byte[] ct_1 = Arrays.copyOfRange(ivPlusCt_1, 16, ivPlusCt_1.length);

            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv_1));
            byte[] decrypted = cipher.doFinal(ct_1);
            LOGGER.info("CBC Plaintext 1 : " + new String(decrypted));

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Remove IV (first 16 bytes) from front of ciphertext
            byte[] ivPlusCt_2 = CipherUtils.hexStringToByteArray(cbcCipherText_2);
            byte[] iv_2 = Arrays.copyOfRange(ivPlusCt_2, 0, 16);
            byte[] ct_2 = Arrays.copyOfRange(ivPlusCt_2, 16, ivPlusCt_2.length);

            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv_2));
            decrypted = cipher.doFinal(ct_2);
            LOGGER.info("CBC Plaintext 2 : " + new String(decrypted));

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

        try {
            String ctrKey = "36f18357be4dbd77f050515c73fcf9f2";
            String ctrCipherText_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
            String ctrCipherText_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

            String toBits = CipherUtils.hexStringToBinaryString(ctrKey);

            LOGGER.info("\tHexChars: " + ctrKey.length() + " - Bits: " + toBits.length() + " - Bytes: "
                    + (toBits.length() / BITS_PER_BYTE));

            int blocks = toBits.length() / AES_BLOCK_SIZE_BITS;
            int remainderBits = toBits.length() % AES_BLOCK_SIZE_BITS;
            int remainderBytes = remainderBits / BITS_PER_BYTE;

            LOGGER.info("\tBlocks: " + blocks + " - Remainder (bits): " + remainderBits + " - Remainder (bytes): "
                    + remainderBytes + " - Whole num of bytes ? : " + ((remainderBits % BITS_PER_BYTE) == 0));

            SecretKey aesKey = new SecretKeySpec(CipherUtils.hexStringToByteArray(ctrKey), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            // Remove IV (first 16 bytes) from front of ciphertext
            byte[] ivPlusCt_1 = CipherUtils.hexStringToByteArray(ctrCipherText_1);
            byte[] iv_1 = Arrays.copyOfRange(ivPlusCt_1, 0, 16);
            byte[] ct_1 = Arrays.copyOfRange(ivPlusCt_1, 16, ivPlusCt_1.length);

            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv_1));
            byte[] decrypted = cipher.doFinal(ct_1);
            LOGGER.info("CTR Plaintext 1 : " + new String(decrypted));

            cipher = Cipher.getInstance("AES/CTR/NoPadding");

            // Remove IV (first 16 bytes) from front of ciphertext
            byte[] ivPlusCt_2 = CipherUtils.hexStringToByteArray(ctrCipherText_2);
            byte[] iv_2 = Arrays.copyOfRange(ivPlusCt_2, 0, 16);
            byte[] ct_2 = Arrays.copyOfRange(ivPlusCt_2, 16, ivPlusCt_2.length);

            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv_2));
            decrypted = cipher.doFinal(ct_2);
            LOGGER.info("CTR Plaintext 2 : " + new String(decrypted));

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

    }
}

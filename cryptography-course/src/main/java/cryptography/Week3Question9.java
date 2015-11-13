package cryptography;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Week3Question9 {
    
    public static void main(String[] args) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, ShortBufferException {
        
        // Use first pair key of zero, cleartext can be anything
        BigInteger y3 = new BigInteger("00000000000000000000000000000000", 16);
        BigInteger x3 = new BigInteger("11111111111111111111111111111111", 16);
        
        // Value generated using AES Encrypt utility on quiz page 
        BigInteger aesEncryptX3X3 = new BigInteger("e56e26f5608b8d268f2556e198a0e01b", 16);
        
        // Any value XOR'ed with zero is itself
        BigInteger f2X3Y3 = aesEncryptX3X3.xor(y3);

        // E(x3, x3) ^ y3 = E(x4, x4) ^ y4
        // As y3 = 0:
        // E(x3, x3) = E(x4, x4) ^ y4
        // y4 = E(x3, x3) ^ E(x4, x4)
        
        BigInteger x4 = new BigInteger("00000000000000000000000000000001", 16);

        // Value generated using AES Encrypt utility on quiz page 
        BigInteger aesEncryptX4X4 = new BigInteger("a17e9f69e4f25a8b8620b4af78eefd6f", 16);
        
        BigInteger y4 = f2X3Y3.xor(aesEncryptX4X4);
        
        System.out.println("y3:\t\t" + y3.toString(16));
        System.out.println("x3:\t\t" + x3.toString(16));
        System.out.println("E(x3,x3):\t" + aesEncryptX3X3.toString(16));
        System.out.println("f2(x3,y3):\t" + f2X3Y3.toString(16));

        System.out.println("x4:\t\t" + x4.toString(16));
        System.out.println("E(x4,x4):\t" + aesEncryptX4X4.toString(16));

        System.out.println("y4:\t\tf2(x3,y3) ^ E(x4,x4)");
        System.out.println("y4:\t\t" + y4.toString(16));        

    }
}
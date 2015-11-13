package cryptography;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Week3Question8 {
    
    public static void main(String[] args) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, ShortBufferException {
        
        // Use first pair key of zero, cleartext can be anything
        BigInteger y1 = new BigInteger("00000000000000000000000000000000", 16);
        BigInteger x1 = new BigInteger("11111111111111111111111111111111", 16);
        
        // Value generated using AES Encrypt utility on quiz page 
        BigInteger aesEncryptY1X1 = new BigInteger("ffa3c7ed04710b98067dae6815e2751f", 16);
        
        // Any value XOR'ed with zero is itself
        BigInteger f1X1Y1 = aesEncryptY1X1.xor(y1);
        
        // Now we have our f1 value, find x2
        // f1 = f2 = E(y2, x2) ^ y2
        // f1 = E(y2, x2) ^ y2
        // f1 ^ y2 = E(y2, x2)     &     x2 = D(y2, E(y2, x2))
        // x2 = D(y2, f1 ^ y2)
        
        // For second pair, set key to 1
        BigInteger y2 = new BigInteger("00000000000000000000000000000001", 16);
        BigInteger f1X1Y1XorKey2 = f1X1Y1.xor(y2);

        System.out.println("y1:\t\t" + y1.toString(16));
        System.out.println("x1:\t\t" + x1.toString(16));
        System.out.println("f1(x1,y1):\t" + f1X1Y1.toString(16));

        System.out.println("y2:\t\t" + y2.toString(16));
        System.out.println("f1(x1,y1) ^ y2:\t" + f1X1Y1XorKey2.toString(16));

        System.out.println("x2:\t\tDecrypt(y2, f1(x1,y1) ^ y2)");
        // Value generated using AES Decrypt utility on quiz page 
        System.out.println("x2:\t\tb20e4254f54a5ba4c3c54554b259cbc9");        

    }
}
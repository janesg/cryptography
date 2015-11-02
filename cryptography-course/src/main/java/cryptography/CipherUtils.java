package cryptography;

import java.nio.charset.StandardCharsets;

public class CipherUtils {

    public static String asciiStringToBinaryString(String str) {

        char[] chars = str.toCharArray();
        StringBuilder bin = new StringBuilder(8 * str.length());

        for (int i = 0; i < chars.length; i++) {
            // Note: Integer.toBinaryString doesn't include leading zeros
            bin.append(leftPad(Integer.toBinaryString((int) chars[i]), '0', 8));
        }

        return bin.toString();
    }

    // This alternative approach works at the byte / bit level
    public static String asciiStringToBinaryString2(String str) {

        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(8 * str.length());

        for (byte b : bytes) {
            for (int i = 0; i <= 7; i++) {
                sb.append(isBitSet(b, i) ? '1' : '0');
            }
        }

        return sb.toString();
    }

    public static String binaryStringToAsciiString(String str) {

        if (str.length() % 8 != 0) {
            // See if stripping out all spaces helps
            str = str.replaceAll(" ", "");

            if (str.length() % 8 != 0) {
                throw new RuntimeException("Unable to convert binary string to ascii string");
            }
        }

        StringBuilder sb = new StringBuilder(str.length() / 8);

        // Convert each block of 8 binary characters to char
        for (int i = 0; i < str.length() - 7; i += 8) {
            String byteStr = str.substring(i, i + 8);
            // radix of 2 denotes binary
            sb.append((char) Integer.parseInt(byteStr, 2));
        }

        return sb.toString();
    }

    public static String asciiStringToHexString(String str) {

        char[] chars = str.toCharArray();
        StringBuilder hex = new StringBuilder(2 * str.length());

        for (int i = 0; i < chars.length; i++) {
            // Note: Integer.toHexString doesn't include leading zeros
            hex.append(leftPad(Integer.toHexString((int) chars[i]), '0', 2));;
        }

        return hex.toString();
    }

    public static String hexStringToAsciiString(String str) {

        if (str.length() % 2 != 0) {
            // See if stripping out all spaces helps
            str = str.replaceAll(" ", "");

            if (str.length() % 2 != 0) {
                throw new RuntimeException("Unable to convert hex string to ascii string");
            }
        }

        StringBuilder sb = new StringBuilder(str.length() / 2);

        // Convert each block of 2 hex characters to char
        for (int i = 0; i < str.length() - 1; i += 2) {
            String byteStr = str.substring(i, i + 2);
            // radix of 16 denotes hex
            sb.append((char) Integer.parseInt(byteStr, 16));
        }

        return sb.toString();
    }

    public static String binaryStringToHexString(String str) {
        if (str.length() % 8 != 0) {
            // See if stripping out all spaces helps
            str = str.replaceAll(" ", "");

            if (str.length() % 8 != 0) {
                throw new RuntimeException("Unable to convert binary string to hex string");
            }
        }

        StringBuilder sb = new StringBuilder(str.length() / 4);

        // Convert each block of 8 binary characters to hex
        for (int i = 0; i < str.length() - 7; i += 8) {
            String byteStr = str.substring(i, i + 8);
            // radix of 2 denotes binary
            // Note: Integer.toHexString doesn't include leading zeros
            sb.append(leftPad(Integer.toHexString(Integer.parseInt(byteStr, 2)), '0', 2));
        }

        return sb.toString();
    }

    public static String hexStringToBinaryString(String str) {
        if (str.length() % 2 != 0) {
            // See if stripping out all spaces helps
            str = str.replaceAll(" ", "");

            if (str.length() % 2 != 0) {
                throw new RuntimeException("Unable to convert hex string to binary string");
            }
        }

        StringBuilder sb = new StringBuilder(str.length() * 4);

        // Convert each block of 2 hex characters to binary
        for (int i = 0; i < str.length() - 1; i += 2) {
            String byteStr = str.substring(i, i + 2);
            // radix of 16 denotes hex
            // Note: Integer.toBinaryString doesn't include leading zeros
            sb.append(leftPad(Integer.toBinaryString(Integer.parseInt(byteStr, 16)), '0', 8));
        }

        return sb.toString();
    }

    public static String asciiStringXorHexString(String str1, String str2) {        
        return hexStringXor(asciiStringToHexString(str1), asciiStringToHexString(str2));
    }
    
    public static String hexStringXor(String hexStr1, String hexStr2) {
        
        int length;
        
        if (hexStr1.length() != hexStr2.length()) {
            throw new RuntimeException("Unable to XOR 2 strings of different lengths");
        } else {
            length = hexStr1.length();
        }
        
        StringBuilder sb = new StringBuilder(length);
        
        // Convert each block of 2 hex characters
        for (int i = 0; i < length - 1; i += 2) {
            String hexChar1 = hexStr1.substring(i, i + 2);
            String hexChar2 = hexStr2.substring(i, i + 2);
            
            // radix of 16 denotes hex            
            int xorRes = Integer.parseInt(hexChar1, 16) ^ Integer.parseInt(hexChar2, 16);
            
            // Note: Integer.toHexString doesn't include leading zeros
            sb.append(leftPad(Integer.toHexString(xorRes), '0', 2));
        }

        return sb.toString();
    }

    public static String encode(String plainText, String key) {
        // We assume that both the plain text and the key are in ASCII
        String expandedKey = repeatString(key, plainText.length());
        
        // Output is the cipher text as HEX string
        return hexStringXor(asciiStringToHexString(plainText), asciiStringToHexString(expandedKey));
    }
    
    public static String decode(String cipherText, String key) {
        // We assume that the cipher text is in HEX and the key is in ASCII
        String expandedKey = repeatString(key, cipherText.length() / 2);
        
        // Output is the plain text as ASCII string
        return hexStringToAsciiString(hexStringXor(cipherText, asciiStringToHexString(expandedKey)));
    }

    private static String repeatString(String str, int requiredLength) {
        
        if (str.length() == requiredLength) {
            return str;
        }

        char[] chars = str.toCharArray();
        StringBuilder sb = new StringBuilder(requiredLength);
        
        for (int i = 0; i < requiredLength ; i++) {
            sb.append(chars[i % chars.length]);            
        }
        
        return sb.toString();
    }

    private static String leftPad(String str, char fillChar, int requiredLength) {

        if (str.length() >= requiredLength) {
            return str;
        }

        StringBuilder sb = new StringBuilder(requiredLength);

        for (int i = 0; i < requiredLength - str.length(); i++) {
            sb.append(fillChar);
        }

        return sb.append(str).toString();
    }

    private static boolean isBitSet(byte b, int bit) {
        // Shift the bit concerned all the way down to right-hand end
        // Bitwise addition to 1 will result in 1 if bit was set
        return ((b >> (7 - bit)) & 1) == 1;
    }

}

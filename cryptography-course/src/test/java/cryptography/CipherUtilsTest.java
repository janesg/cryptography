package cryptography;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CipherUtilsTest {

    @Test
    public void testConvertSingleCharStringToByteString() {
        String str = "D";
        assertEquals("01000100", CipherUtils.asciiStringToBinaryString(str));
    }

    @Test
    public void testConvertSingleCharStringToByteString2() {
        String str = "D";
        assertEquals("01000100", CipherUtils.asciiStringToBinaryString2(str));
    }

    @Test
    public void testConvertByteStringToSingleCharString() {
        String str = "01000100";
        assertEquals("D", CipherUtils.binaryStringToAsciiString(str));
    }

    @Test
    public void testConvertMultiCharStringToByteString() {
        String str = "Dog";
        assertEquals("010001000110111101100111", CipherUtils.asciiStringToBinaryString(str));
    }

    @Test
    public void testConvertMultiCharStringToByteString2() {
        String str = "Dog";
        assertEquals("010001000110111101100111", CipherUtils.asciiStringToBinaryString2(str));
    }

    @Test
    public void testConvertByteStringToMultiCharString() {
        String str = "01000100 01101111 01100111";
        assertEquals("Dog", CipherUtils.binaryStringToAsciiString(str));
    }

    @Test
    public void testConvertSingleCharStringToHexString() {
        String str = "L";
        assertEquals("4c", CipherUtils.asciiStringToHexString(str));
    }

    @Test
    public void testConvertHexStringToSingleCharString() {
        String str = "4c";
        assertEquals("L", CipherUtils.hexStringToAsciiString(str));
    }

    @Test
    public void testConvertMultiCharStringToHexString() {
        String str = "Dog";
        assertEquals("446f67", CipherUtils.asciiStringToHexString(str));
    }

    @Test
    public void testConvertHexStringToMultiCharString() {
        String str = "446f67";
        assertEquals("Dog", CipherUtils.hexStringToAsciiString(str));
    }

    @Test
    public void testConvertBinaryStringToHexString() {
        String str = "010001000110111101100111";
        assertEquals("446f67", CipherUtils.binaryStringToHexString(str));
    }

    @Test
    public void testConvertHexStringToBinaryString() {
        String str = "446f67";
        assertEquals("010001000110111101100111", CipherUtils.hexStringToBinaryString(str));
    }

    @Test
    public void testAsciiStringXor() {
        String str1 = "Dog";
        String str2 = "Cat";

        String xorBin = "000001110000111000010011";
        String xorHex = "070e13";

        assertEquals(xorHex, CipherUtils.asciiStringXorHexString(str1, str2));
        assertEquals(xorBin, CipherUtils.hexStringToBinaryString(CipherUtils.asciiStringXorHexString(str1, str2)));
    }

    @Test
    public void testEncodeDecodeRoundTrip() {
        String message = "This had better work or we're in big, big trouble!";
        String key = "secretSquirrel";

        assertEquals(message, CipherUtils.decode(CipherUtils.encode(message, key), key));
    }

}

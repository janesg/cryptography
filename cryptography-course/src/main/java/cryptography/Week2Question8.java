package cryptography;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Week2Question8 {

    private static final Logger LOGGER = LoggerFactory.getLogger(Week2Question8.class);

    private static String[] msgs = {
            "The most direct computation would be for the enemy to try all 2^r possible keys, one by one.",
            "We see immediately that one needs little information to begin to break down the process.",
            "The significance of this general conjecture, assuming its truth, is easy to see. It means that it may be feasible to design ciphers that are effectively unbreakable.",
            "In this letter I make some remarks on a general principle relevant to enciphering in general and my machine." };

    private static String[] msgs2 = {
            "To consider the resistance of an enciphering process to being broken we should assume that at same times the enemy knows everything but the key being used and to break it needs only discover the key from this information.",
            "An enciphering-deciphering machine (in general outline) of my invention has been sent to your organization.",
            "We see immediately that one needs little information to begin to break down the process.",
            "If qualified opinions incline to believe in the exponential conjecture, then I think we cannot afford not to make use of it." };

    private static final int AES_BLOCK_SIZE_BITS = 128; 
    private static final int BITS_PER_BYTE = 8; 
    
    public static void main(String[] args) {
        
        for (String str : msgs) {
            processMessage(str);
        }
        
        for (String str : msgs2) {
            processMessage(str);
        }
        
    }

    private static void processMessage(String str) {
        LOGGER.info("Message Text: " + str);
        
        String toBits = CipherUtils.asciiStringToBinaryString(str);

        LOGGER.info("\tChars: " + str.length() + " - Bits: " + toBits.length() + 
                    " - Bytes: " + (toBits.length() / BITS_PER_BYTE));
        
        int blocks = toBits.length() / AES_BLOCK_SIZE_BITS;
        int remainderBits = toBits.length() % AES_BLOCK_SIZE_BITS;
        int remainderBytes = remainderBits / BITS_PER_BYTE;
        
        LOGGER.info("\tBlocks: " + blocks + " - Remainder (bits): " + remainderBits + 
                    " - Remainder (bytes): " + remainderBytes + 
                    " - Whole num of bytes ? : " + ((remainderBits % BITS_PER_BYTE) == 0));
    }

}

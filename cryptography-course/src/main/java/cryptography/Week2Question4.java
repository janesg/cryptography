package cryptography;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Week2Question4 {

    private static final Logger LOGGER = LoggerFactory.getLogger(Week2Question4.class);

    private static String[][] ctPairs = { 
                                    {"e86d2de2e1387ae9", "1792d21db645c008"},
                                    {"2d1cfa42c0b1d266", "eea6e3ddb2146dd0"},
                                    {"5f67abaf5210722b", "bbe033c00bc9330e"},
                                    {"7c2822ebfdc48bfb", "325032a9c5e2364b"},
                                 };

    private static String[][] ctPairs2 = { 
                                    {"5f67abaf5210722b", "bbe033c00bc9330e"},
                                    {"9f970f4e932330e4", "6068f0b1b645c008"},
                                    {"4af532671351e2e1", "87a40cfa8dd39154"},
                                    {"9d1a4f78cb28d863", "75e5e3ea773ec3e6"},
                                 };
    
    public static void main(String[] args) {

        printXor(ctPairs);
        printXor(ctPairs2);
        
    }

    private static void printXor(String[][] ctPairs) {
        for (String[] strs : ctPairs) {
            String xorOut = CipherUtils.hexStringXor(strs[0], strs[1]);
            LOGGER.info(strs[0] + " ^ " + strs[1] + " = " + xorOut);            
        }
    }

}

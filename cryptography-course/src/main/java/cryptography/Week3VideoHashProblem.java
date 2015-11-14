package cryptography;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Week3VideoHashProblem {

    private static final Logger LOGGER = LoggerFactory.getLogger(Week3VideoHashProblem.class);
    private static final String FILE_PATH = "C:\\Dev\\Cryptography\\files\\6 - 1 - Introduction (11 min).mp4";
    // private static final String FILE_PATH = "C:\\Dev\\Cryptography\\files\\6 - 2 - Generic birthday attack (16 min).mp4";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        LOGGER.debug("SHA-256 digest length = " + digest.getDigestLength() + " bytes");
        
        // Allow enough room in the chunk array for the 256 bit / 32 byte digest
        byte[] chunk = new byte[1024 + digest.getDigestLength()];
        byte[] prevChunkHash = new byte[digest.getDigestLength()];

        File f = new File(FILE_PATH);
        LOGGER.debug("File length = " + f.length() + " bytes");
        
        // Use Java 7 'try with resources' to handle closing resource automatically
        // Open video file for read-only        
        try (RandomAccessFile rf = new RandomAccessFile(f, "r")) {

            long lastChunkSize = f.length() % 1024 == 0 ? 1024 : f.length() % 1024;
            LOGGER.debug("Last chunk size = " + lastChunkSize);
            long startIndex = f.length() - lastChunkSize;
            LOGGER.debug("Index start = " + startIndex);
            
            // Read backwards through the file in chunks of 1024 bytes
            // Start with the last chunk which will very likely be shorter
            for (long index = startIndex; index >= 0; index -= 1024) {

                rf.seek(index);

                int r = rf.read(chunk, 0, 1024);

                // Is this the shorter last chunk (which gets processed first) ?
                if (r < 1024) {
                    digest.update(chunk, 0, r);
                } else {
                    // Copy the hash of the previous chunk onto end of the current chunk
                    System.arraycopy(prevChunkHash, 0, chunk, 1024, prevChunkHash.length);
                    digest.update(chunk, 0, chunk.length);
                }

                // Calculate the hash value
                prevChunkHash = digest.digest();
            }
        } 

        LOGGER.info("h0 = " + CipherUtils.byteArrayToHexString(prevChunkHash));
    }
}

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by makjdrn on 2015-11-26.
 */
public class test {
    public static void main(String[] args) {
        int bitlen = 7680;
        Random rnd = new SecureRandom();
        BigInteger bi = new BigInteger(bitlen, 1000, rnd);
        System.out.println(bi + "\n " + rnd + "\n" + bi.bitLength());
    }
}

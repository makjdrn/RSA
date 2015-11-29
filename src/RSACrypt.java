import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

/**
 * Created by makjdrn on 2015-11-26.
 */
public class RSACrypt {
    private BigInteger p;
    private BigInteger q;
    private static BigInteger N;
    private BigInteger e;
    private BigInteger phi;
    private static BigInteger d;
    private static int bitlength;
    private Random r;
    public static String privatekeyFileName;
    public static String publickeyFileName;
    public static String InputFileName;
    public static String EncryptedFileName;
    public String DecryptedFileName;

    public RSACrypt() throws IOException {
        r = new SecureRandom();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength/2, r);

        while(phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
            e = e.add(BigInteger.ONE);
        d = e.modInverse(phi);
        BufferedWriter privkey = new BufferedWriter(new FileWriter(privatekeyFileName));
        privkey.write(String.valueOf(d));
        privkey.close();
        BufferedWriter pubkey = new BufferedWriter(new FileWriter(publickeyFileName));
        pubkey.write(String.valueOf(N));
        pubkey.close();

    }
    public RSACrypt(BigInteger e, BigInteger d, BigInteger N) {
        this.e = e;
        RSACrypt.d = d;
        RSACrypt.N = N;
    }
    public static void main(String[] args) throws IOException {

        String path = args[1];
        if(args[2].equals("E")) {
            bitlength = Integer.parseInt(args[0]);
            publickeyFileName = args[1].trim();
            privatekeyFileName = args[2].trim();
            RSACrypt trsa = new RSACrypt();
            String text = new Scanner(new File(path)).useDelimiter("\\Z").next();
            System.out.println(text.length() + "\ntext: " + text  + " N: " + N + " d: " + d);
            BigInteger plaintext = new BigInteger(text.getBytes());
            System.out.println(plaintext.bitLength() + "\nplaintext: " + plaintext);
            BigInteger ciphertext = trsa.encrypt(plaintext);
            //String senc = bytesToString(encrypted);
            System.out.println(ciphertext.bitLength() + "\nciphertext: " + ciphertext);
            WriteToFile(ciphertext, path);
        }
        else if(args[2].equals("D")) {
            //byte[] btext = Files.readAllBytes(p);
            publickeyFileName = args[1].trim();
            InputFileName = args[2].trim();
            EncryptedFileName = args[3].trim();
            Scanner sc = new Scanner(new File(path));
            d = new BigInteger(pub);
            String nn = sc.useDelimiter("\n").next();
            N = new BigInteger(nn);
            System.out.println(text2.length() + "\ntext: " + text2 + " N: " + N + " d: " + d);
            ///System.out.println(ciphertext2.bitLength() + "\nciphertext: " + ciphertext2);
            String s;
            BigInteger ciphertext2 = new BigInteger(text2);
            BigInteger bgc;
            BigInteger plaintext2;
            String scipher = ciphertext2.toString();
            while(scipher.length() >= 254) {
                String ss = scipher.substring(0,254);
                bgc = new BigInteger(ss);
                plaintext2 = decrypt(bgc);
                s = new String(plaintext2.toByteArray());
                System.out.println(s + "\n " + plaintext2.bitLength());
                WriteToFile(plaintext2, path);
                scipher = scipher.substring(255, scipher.length());
            }
            plaintext2 = decrypt(ciphertext2);
            //s = new String(plaintext2.toByteArray());
            WriteToFile(plaintext2, path);
        }
    }

    private static void WriteToFile(BigInteger mess, String path) throws IOException {
        FileWriter fw = new FileWriter(path);
        fw.write(String.valueOf(mess) + "\n" + d + "\n" + N);
        fw.flush();
        fw.close();
    }

    private static String bytesToString(byte[] encrypted) {
        String m = "";
        for(byte b : encrypted)
            m += Byte.toString(b);
        return m;
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e,N);
    }
    public String encrypt(String message) {
        return new String((new BigInteger(message)).modPow(e, N).toByteArray());
    }
    public static BigInteger decrypt(BigInteger message) {
        //byte[] b = message.getBytes("UTF-8");
        System.out.println(message.bitLength());
        return message.modPow(d, N);
    }
    public String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, N).toByteArray());
    }
}

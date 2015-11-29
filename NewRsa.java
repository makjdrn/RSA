import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import sun.misc.BASE64Decoder;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

/**
 * Created by makjdrn on 2015-11-27.
 */
public class NewRsa {
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

    public NewRsa() throws IOException {
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
    public static void main(String[] args) throws IOException {
        System.out.println("hello");
        if(args.length < 4) {
            bitlength = Integer.parseInt(args[0]);
            publickeyFileName = args[1].trim();
            privatekeyFileName = args[2].trim();
            NewRsa nrsa = new NewRsa();
        }
        else if(args[4].equals("E")) {
            publickeyFileName = args[1].trim();
            InputFileName = args[2].trim();
            EncryptedFileName = args[3].trim();
            encrypt(publickeyFileName, InputFileName, EncryptedFileName);
        }
    }

    private static void encrypt(String publickeyFileName, String inputFileName, String encryptedFileName) {
        try {
            //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            String value = "";
            String key = readFileAsString(publickeyFileName);
            BASE64Decoder b64 = new BASE64Decoder();
            AsymmetricKeyParameter publicKey =
                    (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64.decodeBuffer(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            String inputdata = readFileAsString(inputFileName);
            byte[] messageBytes = inputdata.getBytes();
            int i = 0;
            int len = e.getInputBlockSize();
            while (i < messageBytes.length)
            {
                if (i + len > messageBytes.length)
                    len = messageBytes.length - i;

                byte[] hexEncodedCipher = e.processBlock(messageBytes, i, len);
                value = value + getHexString(hexEncodedCipher);
                i += e.getInputBlockSize();
            }

            System.out.println(value);
            BufferedWriter out = new BufferedWriter(new FileWriter(encryptedFileName));
            out.write(value);
            out.close();

        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    private static String getHexString(byte[] b) {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                    Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
    private static String readFileAsString(String filePath)
            throws java.io.IOException{
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(
                new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        System.out.println(fileData.toString());
        return fileData.toString();
    }
}

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class ThresholdScheme {
    public static final String description =
    "Shamir's (k,n) secret sharing threshold scheme, with the secret bytes " +
    "padded in front with a byte of value 1, a byte of the xor of even " +
    "secret bytes and a byte of the xor of odd secret bytes";

    public final BigInteger prime;
    public final BigInteger[][] points;

    private static final Random rng = new SecureRandom();

    public ThresholdScheme(byte[] originalSecret, int k, int n) {
        byte[] padded = prePadOneAndEvenOddXor(originalSecret);
        BigInteger secret = new BigInteger(padded);

        int secretLength = secret.bitLength();
        prime = BigInteger.probablePrime(secretLength + 1, rng);

        BigInteger[] coeff = new BigInteger[k];
        coeff[0] = secret;
        for(int i = 1; i < coeff.length; ++i)
            coeff[i] = new BigInteger(secretLength, rng);

        points = new BigInteger[n][];
        for(int i = 0; i < points.length; ++i) {
            BigInteger x = BigInteger.valueOf(i + 1);
            BigInteger fx = evalPolynomialMod(coeff, x, prime);
            points[i] = new BigInteger[] {x, fx};
        }
    }

    public static BigInteger evalPolynomialMod(BigInteger[] coeff,
        BigInteger x, BigInteger m) {
        BigInteger ret = coeff[coeff.length - 1];
        for(int i = coeff.length - 2; i >= 0; --i)
            ret = ret.multiply(x).add(coeff[i]).mod(m);
        return ret;
    }

    public static byte[] evenOddXor(byte[] bytes) {
        byte[] xors = new byte[2];
        for(int i = 0; i < bytes.length; ++i)
            xors[i % 2] ^= bytes[i];
        return xors;
    }

    public static byte[] prePadOneAndEvenOddXor(byte[] bytes) {
        byte[] xors = evenOddXor(bytes);

        byte[] padded = new byte[bytes.length + 3];
        padded[0] = 1;
        padded[1] = xors[0];
        padded[2] = xors[1];
        for(int i = 0; i < bytes.length; ++i)
            padded[i + 3] = bytes[i];

        return padded;
    }

    public static byte[] reconstructSecret(BigInteger prime, BigInteger[][] points) {
        BigInteger coeff0 = BigInteger.ZERO;

        for(int i = 0; i < points.length; ++i) {
            BigInteger x_i = points[i][0], y_i = points[i][1],
                       top = y_i, bot = BigInteger.ONE;

            for(int j = 0; j < points.length; ++j)
                if(j != i) {
                    BigInteger x_j = points[j][0];
                    top = top.multiply(x_j);
                    bot = bot.multiply(x_j.subtract(x_i));
                }
            System.out.println("x_i = " + x_i + ", y_i = " + y_i);
            System.out.println("top = " + top + ", bot = " + bot);

            //BigDecimal quotient = new BigDecimal(top).divide(new BigDecimal(bot), 10, RoundingMode.HALF_UP);
            coeff0 = coeff0.add(top.multiply(bot.modInverse(prime))).mod(prime);
            System.out.println("coeff0 = " + coeff0);
        }

        //System.out.println("coeff = " + coeff0.setScale(0, RoundingMode.HALF_UP).toBigInteger().mod(prime));

        BigInteger secret = coeff0;//coeff0.setScale(0, RoundingMode.HALF_UP).toBigInteger().mod(prime);

        byte[] padded = secret.toByteArray();
        byte[] originalSecret = Arrays.copyOfRange(padded, 3, padded.length);
        byte[] xors = evenOddXor(originalSecret);

        if(padded[0] != 1 || padded[1] != xors[0] || padded[2] != xors[1]) {
            System.out.println("padded[0] = " + padded[0]);
            System.out.println("padded[1] = " + padded[1] + " xors[0] = " + xors[0]);
            System.out.println("padded[2] = " + padded[2] + " xors[1] = " + xors[1]);
            throw new IllegalStateException("Constructed secret invalid: " +
                "too few points or wrong prime/points!");
        }

        return originalSecret;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        String p = prime.toString();
        sb.append(String.format("Prime %s\nPoints:\n", p));
        for(int i = 0; i < points.length; ++i)
            sb.append(String.format("%s, %s\n",
                points[i][0], points[i][1]));
        return sb.toString();
    }

    public static void main(String[] args) {
        byte[] secret = args[0].getBytes();
        ThresholdScheme scheme = new ThresholdScheme(secret, 3, 6);
        System.out.println(scheme);

        BigInteger[][] three = new BigInteger[3][];
        three[0] = scheme.points[Integer.parseInt(args[1])];
        three[1] = scheme.points[Integer.parseInt(args[2])];
        three[2] = scheme.points[Integer.parseInt(args[3])];

        byte[] reconstructed = reconstructSecret(scheme.prime, three);
        System.out.println(new String(reconstructed));
    }
}

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

public class ThresholdScheme {
    public static final String description =
    "Shamir's (k,n) secret sharing threshold scheme, with the secret bytes " +
    "padded in front with a byte of value 1, a byte of the xor of even " +
    "secret bytes and a byte of the xor of odd secret bytes";

    public final BigInteger prime;
    public final Set<XY> points;

    private static final Random rng = new SecureRandom();

    public ThresholdScheme(byte[] originalSecret, int k, int n) {
        if(originalSecret == null || originalSecret.length == 0)
            throw new IllegalArgumentException("Secret must be at least one byte");
        if(!(2 <= k && k <= n))
            throw new IllegalArgumentException("Assertion failed: 2 <= k <= n");

        byte[] padded = prePadOneAndEvenOddXor(originalSecret);
        BigInteger secret = new BigInteger(padded);

        int secretLength = secret.bitLength();
        prime = BigInteger.probablePrime(secretLength + 1, rng);

        BigInteger[] coeff = new BigInteger[k];
        coeff[0] = secret;
        for(int i = 1; i < coeff.length; ++i)
            coeff[i] = new BigInteger(secretLength, rng);

        Set<XY> p = new TreeSet<>();
        for(int i = 0; i < n; ++i) {
            BigInteger x = BigInteger.valueOf(i + 1);
            BigInteger fx = evalPolynomialMod(coeff, x, prime);

            p.add(new XY(x, fx));
        }

        points = Collections.unmodifiableSet(p);
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

    public static byte[] reconstructSecret(BigInteger prime, Collection<XY> points) {
        BigInteger coeff0 = BigInteger.ZERO;

        for(XY point : points) {
            BigInteger top = point.y, bot = BigInteger.ONE;

            for(XY p : points)
                if(!p.x.equals(point.x)) { // don't want divisor of 0
                    top = top.multiply(p.x);
                    bot = bot.multiply(p.x.subtract(point.x));
                }

            BigInteger quot = top.multiply(bot.modInverse(prime)).mod(prime);
            coeff0 = coeff0.add(quot).mod(prime);
        }

        BigInteger secret = coeff0;

        byte[] padded = secret.toByteArray();
        byte[] originalSecret =
            Arrays.copyOfRange(padded, Math.min(3, padded.length), padded.length);
        byte[] xors = evenOddXor(originalSecret);

        if(padded.length < 3 || padded[0] != 1 || padded[1] != xors[0] || padded[2] != xors[1]) {
            throw new IllegalStateException("Reconstructed secret is invalid: " +
                "too few points or wrong prime/points!");
        }

        return originalSecret;
    }

    @Override
    public String toString() {
        return String.format("Prime: %s\nPoints:\n%s", prime, points);
    }

    public static void main(String[] args) {
        byte[] secret = args[0].getBytes();
        ThresholdScheme scheme = new ThresholdScheme(secret, 4, 16);
        System.out.println(scheme);

        /*
        List<XY> points = new ArrayList<>(scheme.points);

        for(int i = 0; i < 15; ++i) {
            Collections.shuffle(points);
            List<XY> p = new ArrayList<>();
            for(int j = 0; j < 8; ++j)
                p.add(points.get(j));

            System.out.println("Trying with " + p);
            try {
                byte[] reconstructed = reconstructSecret(scheme.prime, p);
                System.out.println("It worked!!");
            } catch (IllegalStateException e) {
                System.out.println("Didn't work");
            }
        }
        */
    }

    public static class XY implements Comparable<XY> {
        public final BigInteger x;
        public final BigInteger y;
        public XY(BigInteger x, BigInteger y) { this.x = x; this.y = y; }

        @Override
        public boolean equals(Object o) {
            if(o == null) return false;
            if(this == o) return true;
            if(o instanceof XY) {
                XY xy = (XY) o;
                return x.equals(xy.x) && y.equals(xy.y);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return x.hashCode() ^ y.hashCode();
        }

        @Override
        public String toString() {
            return String.format("[%s, %s]", x, y);
        }

        @Override
        public int compareTo(XY other) {
            int a = x.compareTo(other.x);
            if(a != 0) return a;
            return y.compareTo(other.y);
        }
    }
}

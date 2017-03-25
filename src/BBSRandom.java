import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;


public class BBSRandom extends Random {
    public static BigInteger BlumPrime(int bitLength, Random rnd) {
        while(true) {
            BigInteger p = BigInteger.probablePrime(bitLength, rnd);
            if(p.testBit(1) && p.testBit(0))
                return p;
        }
    }

    public static BigInteger[] BlumIntegerAndFactors(int primeBitLength, Random rnd) {
        BigInteger[] ret = new BigInteger[3];
        ret[1] = BlumPrime(primeBitLength, rnd);
        do {
            ret[2] = BlumPrime(primeBitLength, rnd);
        } while(ret[2].equals(ret[1]));

        ret[0] = ret[1].multiply(ret[2]);
        return ret;
    }

    public static BigInteger randomModCoprime(BigInteger n, Random rnd) {
        while(true) {
            BigInteger r = new BigInteger(n.bitLength(), rnd);
            if(r.compareTo(n) < 0)
                if(r.gcd(n).compareTo(BigInteger.valueOf(2)) < 0)
                    return r;
        }
    }

    public static int numberOfSecureBits(BigInteger i) {
        return BigInteger.valueOf(i.bitLength()).bitLength() - 1;
    }

    public static void main(String[] args) {
        System.out.println(BlumPrime(2, new Random()).toString(16));
    }

    @Override
    protected int next(int bits) {
        return 0;
    }

    private int shiftMoreBits(int curr, int bits) {
        int bitBlockIndex = (int) (streamIndex % secureBitsPerX);
        int bitsToShift = Math.min(secureBitsPerX - bitBlockIndex, bits);
        int bitsToShiftMask = (int) ((1L << bitsToShift) - 1);
        int block = x_t.intValue() >>> (secureBitsPerX - bitBlockIndex - bitsToShift);
        

    }

    protected void nextX() {

    }

    public final BigInteger n;
    public final int secureBitsPerX;
    protected long streamIndex;
    protected BigInteger x_t;

    // encrypting with public key
    public BBSRandom(BigInteger modulus, Random rng) {
        n = modulus;
        BigInteger x = randomModCoprime(n, rng);
        x_t = x.modPow(BigInteger.valueOf(2), n);
        t = 0;
    }

    public static class RandomAccess extends BBSRandom {
        public final BigInteger p;
        public final BigInteger q;
        public final BigInteger x_0;

        // creating a new public-private key pair
        public RandomAccess(int primeBitLength, Random rng) {
            BigInteger[] blum = BlumIntegerAndFactors(primeBitLength, rng);
            n = blum[0];
            p = blum[1];
            q = blum[2];
            BigInteger x = randomModCoprime(n, rng);
            x_0 = x.modPow(BigInteger.valueOf(2), n);
        }

        // decrypting with private key
        public RandomAccess(BigInteger p, BigInteger q, BigInteger x_t, long t) {
            this.p = p; this.q = q; this.x_t = x_t; this.t = t;
            // compute x_0
        }
    }
}

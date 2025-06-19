using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Utilities
{
    /**
     * BigInteger utilities.
     */
    public abstract class BigIntegers
    {
        public static readonly BigInteger Zero = BigInteger.Zero;
        public static readonly BigInteger One = BigInteger.One;

        private const int MaxIterations = 1000;

        /**
        * Return the passed in value as an unsigned byte array.
        *
        * @param value value to be converted.
        * @return a byte array without a leading zero byte if present in the signed encoding.
        */
        public static byte[] AsUnsignedByteArray(
            BigInteger n)
        {
            return n.ToByteArrayUnsigned();
        }

        /**
         * Return the passed in value as an unsigned byte array of specified length, zero-extended as necessary.
         *
         * @param length desired length of result array.
         * @param n value to be converted.
         * @return a byte array of specified length, with leading zeroes as necessary given the size of n.
         */
        public static byte[] AsUnsignedByteArray(int length, BigInteger n)
        {
            byte[] bytes = n.ToByteArrayUnsigned();

            if (bytes.Length > length)
                throw new ArgumentException("standard length exceeded", "n");

            if (bytes.Length == length)
                return bytes;

            byte[] tmp = new byte[length];
            Array.Copy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);
            return tmp;
        }

        public static BigInteger FromUnsignedByteArray(byte[] buf)
        {
            return new BigInteger(1, buf);
        }

        public static BigInteger FromUnsignedByteArray(byte[] buf, int off, int length)
        {
            byte[] mag = buf;
            if (off != 0 || length != buf.Length)
            {
                mag = new byte[length];
                Array.Copy(buf, off, mag, 0, length);
            }
            return new BigInteger(1, mag);
        }

        /**
        * Return a random BigInteger not less than 'min' and not greater than 'max'
        * 
        * @param min the least value that may be generated
        * @param max the greatest value that may be generated
        * @param random the source of randomness
        * @return a random BigInteger value in the range [min,max]
        */
        public static BigInteger CreateRandomInRange(
            BigInteger		min,
            BigInteger		max,
            // TODO Should have been just Random class
            SecureRandom	random)
        {
            int cmp = min.CompareTo(max);
            if (cmp >= 0)
            {
                if (cmp > 0)
                    throw new ArgumentException("'min' may not be greater than 'max'");

                return min;
            }

            if (min.BitLength > max.BitLength / 2)
            {
                return CreateRandomInRange(BigInteger.Zero, max.Subtract(min), random).Add(min);
            }

            for (int i = 0; i < MaxIterations; ++i)
            {
                BigInteger x = new BigInteger(max.BitLength, random);
                if (x.CompareTo(min) >= 0 && x.CompareTo(max) <= 0)
                {
                    return x;
                }
            }

            // fall back to a faster (restricted) method
            return new BigInteger(max.Subtract(min).BitLength - 1, random).Add(min);
        }

        /**
         * Return a positive BigInteger in the range of 0 to 2**bitLength - 1.
         *
         * @param bitLength maximum bit length for the generated BigInteger.
         * @param random a source of randomness.
         * @return a positive BigInteger
         */
        public static BigInteger CreateRandomBigInteger(int bitLength, SecureRandom random)
        {
            return new BigInteger(1, CreateRandom(bitLength, random));
        }

        private static byte[] CreateRandom(int bitLength, SecureRandom random)
        {
            if (bitLength < 1)
                throw new ArgumentException("bitLength must be at least 1");

            int nBytes = (bitLength + 7) / 8;

            byte[] rv = new byte[nBytes];
            random.NextBytes(rv);

            // strip off any excess bits in the MSB
            int xBits = 8 * nBytes - bitLength;
            rv[0] &= (byte)(0xFFU >> xBits);

            return rv;
        }

        public static BigInteger ModOddInverse(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", "M");
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (X.SignValue < 0 || X.CompareTo(M) >= 0)
            {
                X = X.Mod(M);
            }

            int bits = M.BitLength;
            uint[] m = Nat.FromBigInteger(bits, M);
            uint[] x = Nat.FromBigInteger(bits, X);
            int len = m.Length;
            uint[] z = Nat.Create(len);
            if (0 == Mod.ModOddInverse(m, x, z))
                throw new ArithmeticException("BigInteger not invertible");
            return Nat.ToBigInteger(len, z);
        }

        public static BigInteger ModOddInverseVar(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", "M");
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (M.Equals(One))
                return Zero;
            if (X.SignValue < 0 || X.CompareTo(M) >= 0)
            {
                X = X.Mod(M);
            }
            if (X.Equals(One))
                return One;

            int bits = M.BitLength;
            uint[] m = Nat.FromBigInteger(bits, M);
            uint[] x = Nat.FromBigInteger(bits, X);
            int len = m.Length;
            uint[] z = Nat.Create(len);
            if (!Mod.ModOddInverseVar(m, x, z))
                throw new ArithmeticException("BigInteger not invertible");
            return Nat.ToBigInteger(len, z);
        }
    }
}

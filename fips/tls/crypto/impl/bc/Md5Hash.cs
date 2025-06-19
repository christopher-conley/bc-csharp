using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class Md5Hash
        : TlsHash
    {
        // round 1 left rotates
        private const int S11 = 7;
        private const int S12 = 12;
        private const int S13 = 17;
        private const int S14 = 22;

        // round 2 left rotates
        private const int S21 = 5;
        private const int S22 = 9;
        private const int S23 = 14;
        private const int S24 = 20;

        // round 3 left rotates
        private const int S31 = 4;
        private const int S32 = 11;
        private const int S33 = 16;
        private const int S34 = 23;

        // round 4 left rotates
        private const int S41 = 6;
        private const int S42 = 10;
        private const int S43 = 15;
        private const int S44 = 21;

        private readonly byte[] m_buf = new byte[64];

        private int m_bufPos = 0;
        private long m_byteCount = 0;

        private uint m_H1 = 0x67452301;
        private uint m_H2 = 0xefcdab89;
        private uint m_H3 = 0x98badcfe;
        private uint m_H4 = 0x10325476;

        internal Md5Hash()
        {
        }

        private Md5Hash(Md5Hash that)
        {
            ImplCopy(that);
        }

        public void Update(byte[] input, int inOff, int inLen)
        {
            if (inLen < 1)
                return;

            m_byteCount += inLen;

            int available = 64 - m_bufPos;
            if (inLen < available)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, inLen);
                m_bufPos += inLen;
                return;
            }

            int inPos = 0;
            if (m_bufPos > 0)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, available);
                ProcessBlock(m_buf, 0);
                inPos += available;
            }

            int remaining;
            while ((remaining = inLen - inPos) >= 64)
            {
                ProcessBlock(input, inOff + inPos);
                inPos += 64;
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
        }

        public byte[] CalculateHash()
        {
            byte[] result = new byte[16];
            CalculateHash(result, 0);
            return result;
        }

        public void Reset()
        {
            ImplReset();
        }

        internal void CalculateHash(byte[] output, int outOff)
        {
            m_buf[m_bufPos++] = 0x80;

            if (m_bufPos > 56)
            {
                Arrays.Fill(m_buf, m_bufPos, 64, 0x00);
                ProcessBlock(m_buf, 0);
                m_bufPos = 0;
            }

            Arrays.Fill(m_buf, m_bufPos, 56, 0x00);

            long bitLength = m_byteCount << 3;
            Core.Pack.Int64_To_LE(bitLength, m_buf, 56);
            ProcessBlock(m_buf, 0);

            Core.Pack.Int32_To_LE((int)m_H1, output, outOff + 0);
            Core.Pack.Int32_To_LE((int)m_H2, output, outOff + 4);
            Core.Pack.Int32_To_LE((int)m_H3, output, outOff + 8);
            Core.Pack.Int32_To_LE((int)m_H4, output, outOff + 12);

            ImplReset();
        }

        internal Md5Hash Copy()
        {
            return new Md5Hash(this);
        }

        internal void Reset(Md5Hash that)
        {
            ImplCopy(that);
        }

        private void ImplCopy(Md5Hash that)
        {
            Array.Copy(that.m_buf, this.m_buf, 64);

            this.m_bufPos = that.m_bufPos;
            this.m_byteCount = that.m_byteCount;

            this.m_H1 = that.m_H1;
            this.m_H2 = that.m_H2;
            this.m_H3 = that.m_H3;
            this.m_H4 = that.m_H4;
        }

        private void ImplReset()
        {
            Arrays.Fill(m_buf, 0, 64, 0x00);

            m_bufPos = 0;
            m_byteCount = 0;

            m_H1 = 0x67452301;
            m_H2 = 0xefcdab89;
            m_H3 = 0x98badcfe;
            m_H4 = 0x10325476;
        }

        private void ProcessBlock(byte[] buf, int off)
        {
            uint x00 = (uint)Core.Pack.LE_To_Int32(buf, off +  0);
            uint x01 = (uint)Core.Pack.LE_To_Int32(buf, off +  4);
            uint x02 = (uint)Core.Pack.LE_To_Int32(buf, off +  8);
            uint x03 = (uint)Core.Pack.LE_To_Int32(buf, off + 12);
            uint x04 = (uint)Core.Pack.LE_To_Int32(buf, off + 16);
            uint x05 = (uint)Core.Pack.LE_To_Int32(buf, off + 20);
            uint x06 = (uint)Core.Pack.LE_To_Int32(buf, off + 24);
            uint x07 = (uint)Core.Pack.LE_To_Int32(buf, off + 28);
            uint x08 = (uint)Core.Pack.LE_To_Int32(buf, off + 32);
            uint x09 = (uint)Core.Pack.LE_To_Int32(buf, off + 36);
            uint x10 = (uint)Core.Pack.LE_To_Int32(buf, off + 40);
            uint x11 = (uint)Core.Pack.LE_To_Int32(buf, off + 44);
            uint x12 = (uint)Core.Pack.LE_To_Int32(buf, off + 48);
            uint x13 = (uint)Core.Pack.LE_To_Int32(buf, off + 52);
            uint x14 = (uint)Core.Pack.LE_To_Int32(buf, off + 56);
            uint x15 = (uint)Core.Pack.LE_To_Int32(buf, off + 60);

            uint a = m_H1;
            uint b = m_H2;
            uint c = m_H3;
            uint d = m_H4;

            //
            // Round 1 - F cycle, 16 times.
            //
            a = Integers.RotateLeft((a + F(b, c, d) + x00 + 0xd76aa478), S11) + b;
            d = Integers.RotateLeft((d + F(a, b, c) + x01 + 0xe8c7b756), S12) + a;
            c = Integers.RotateLeft((c + F(d, a, b) + x02 + 0x242070db), S13) + d;
            b = Integers.RotateLeft((b + F(c, d, a) + x03 + 0xc1bdceee), S14) + c;
            a = Integers.RotateLeft((a + F(b, c, d) + x04 + 0xf57c0faf), S11) + b;
            d = Integers.RotateLeft((d + F(a, b, c) + x05 + 0x4787c62a), S12) + a;
            c = Integers.RotateLeft((c + F(d, a, b) + x06 + 0xa8304613), S13) + d;
            b = Integers.RotateLeft((b + F(c, d, a) + x07 + 0xfd469501), S14) + c;
            a = Integers.RotateLeft((a + F(b, c, d) + x08 + 0x698098d8), S11) + b;
            d = Integers.RotateLeft((d + F(a, b, c) + x09 + 0x8b44f7af), S12) + a;
            c = Integers.RotateLeft((c + F(d, a, b) + x10 + 0xffff5bb1), S13) + d;
            b = Integers.RotateLeft((b + F(c, d, a) + x11 + 0x895cd7be), S14) + c;
            a = Integers.RotateLeft((a + F(b, c, d) + x12 + 0x6b901122), S11) + b;
            d = Integers.RotateLeft((d + F(a, b, c) + x13 + 0xfd987193), S12) + a;
            c = Integers.RotateLeft((c + F(d, a, b) + x14 + 0xa679438e), S13) + d;
            b = Integers.RotateLeft((b + F(c, d, a) + x15 + 0x49b40821), S14) + c;

            //
            // Round 2 - G cycle, 16 times.
            //
            a = Integers.RotateLeft((a + G(b, c, d) + x01 + 0xf61e2562), S21) + b;
            d = Integers.RotateLeft((d + G(a, b, c) + x06 + 0xc040b340), S22) + a;
            c = Integers.RotateLeft((c + G(d, a, b) + x11 + 0x265e5a51), S23) + d;
            b = Integers.RotateLeft((b + G(c, d, a) + x00 + 0xe9b6c7aa), S24) + c;
            a = Integers.RotateLeft((a + G(b, c, d) + x05 + 0xd62f105d), S21) + b;
            d = Integers.RotateLeft((d + G(a, b, c) + x10 + 0x02441453), S22) + a;
            c = Integers.RotateLeft((c + G(d, a, b) + x15 + 0xd8a1e681), S23) + d;
            b = Integers.RotateLeft((b + G(c, d, a) + x04 + 0xe7d3fbc8), S24) + c;
            a = Integers.RotateLeft((a + G(b, c, d) + x09 + 0x21e1cde6), S21) + b;
            d = Integers.RotateLeft((d + G(a, b, c) + x14 + 0xc33707d6), S22) + a;
            c = Integers.RotateLeft((c + G(d, a, b) + x03 + 0xf4d50d87), S23) + d;
            b = Integers.RotateLeft((b + G(c, d, a) + x08 + 0x455a14ed), S24) + c;
            a = Integers.RotateLeft((a + G(b, c, d) + x13 + 0xa9e3e905), S21) + b;
            d = Integers.RotateLeft((d + G(a, b, c) + x02 + 0xfcefa3f8), S22) + a;
            c = Integers.RotateLeft((c + G(d, a, b) + x07 + 0x676f02d9), S23) + d;
            b = Integers.RotateLeft((b + G(c, d, a) + x12 + 0x8d2a4c8a), S24) + c;

            //
            // Round 3 - H cycle, 16 times.
            //
            a = Integers.RotateLeft((a + H(b, c, d) + x05 + 0xfffa3942), S31) + b;
            d = Integers.RotateLeft((d + H(a, b, c) + x08 + 0x8771f681), S32) + a;
            c = Integers.RotateLeft((c + H(d, a, b) + x11 + 0x6d9d6122), S33) + d;
            b = Integers.RotateLeft((b + H(c, d, a) + x14 + 0xfde5380c), S34) + c;
            a = Integers.RotateLeft((a + H(b, c, d) + x01 + 0xa4beea44), S31) + b;
            d = Integers.RotateLeft((d + H(a, b, c) + x04 + 0x4bdecfa9), S32) + a;
            c = Integers.RotateLeft((c + H(d, a, b) + x07 + 0xf6bb4b60), S33) + d;
            b = Integers.RotateLeft((b + H(c, d, a) + x10 + 0xbebfbc70), S34) + c;
            a = Integers.RotateLeft((a + H(b, c, d) + x13 + 0x289b7ec6), S31) + b;
            d = Integers.RotateLeft((d + H(a, b, c) + x00 + 0xeaa127fa), S32) + a;
            c = Integers.RotateLeft((c + H(d, a, b) + x03 + 0xd4ef3085), S33) + d;
            b = Integers.RotateLeft((b + H(c, d, a) + x06 + 0x04881d05), S34) + c;
            a = Integers.RotateLeft((a + H(b, c, d) + x09 + 0xd9d4d039), S31) + b;
            d = Integers.RotateLeft((d + H(a, b, c) + x12 + 0xe6db99e5), S32) + a;
            c = Integers.RotateLeft((c + H(d, a, b) + x15 + 0x1fa27cf8), S33) + d;
            b = Integers.RotateLeft((b + H(c, d, a) + x02 + 0xc4ac5665), S34) + c;

            //
            // Round 4 - K cycle, 16 times.
            //
            a = Integers.RotateLeft((a + K(b, c, d) + x00 + 0xf4292244), S41) + b;
            d = Integers.RotateLeft((d + K(a, b, c) + x07 + 0x432aff97), S42) + a;
            c = Integers.RotateLeft((c + K(d, a, b) + x14 + 0xab9423a7), S43) + d;
            b = Integers.RotateLeft((b + K(c, d, a) + x05 + 0xfc93a039), S44) + c;
            a = Integers.RotateLeft((a + K(b, c, d) + x12 + 0x655b59c3), S41) + b;
            d = Integers.RotateLeft((d + K(a, b, c) + x03 + 0x8f0ccc92), S42) + a;
            c = Integers.RotateLeft((c + K(d, a, b) + x10 + 0xffeff47d), S43) + d;
            b = Integers.RotateLeft((b + K(c, d, a) + x01 + 0x85845dd1), S44) + c;
            a = Integers.RotateLeft((a + K(b, c, d) + x08 + 0x6fa87e4f), S41) + b;
            d = Integers.RotateLeft((d + K(a, b, c) + x15 + 0xfe2ce6e0), S42) + a;
            c = Integers.RotateLeft((c + K(d, a, b) + x06 + 0xa3014314), S43) + d;
            b = Integers.RotateLeft((b + K(c, d, a) + x13 + 0x4e0811a1), S44) + c;
            a = Integers.RotateLeft((a + K(b, c, d) + x04 + 0xf7537e82), S41) + b;
            d = Integers.RotateLeft((d + K(a, b, c) + x11 + 0xbd3af235), S42) + a;
            c = Integers.RotateLeft((c + K(d, a, b) + x02 + 0x2ad7d2bb), S43) + d;
            b = Integers.RotateLeft((b + K(c, d, a) + x09 + 0xeb86d391), S44) + c;

            m_H1 += a;
            m_H2 += b;
            m_H3 += c;
            m_H4 += d;
        }

        private static uint F(uint u, uint v, uint w)
        {
            return (u & v) | (~u & w);
        }

        private static uint G(uint u, uint v, uint w)
        {
            return (u & w) | (v & ~w);
        }

        private static uint H(uint u, uint v, uint w)
        {
            return u ^ v ^ w;
        }

        private static uint K(uint u, uint v, uint w)
        {
            return v ^ (u | ~w);
        }
    }
}

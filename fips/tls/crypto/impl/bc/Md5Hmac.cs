using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class Md5Hmac
        : TlsHmac
    {
        private const int BlockLength = 64;
        private const int DigestSize = 16;

        private const byte IPAD = (byte)0x36;
        private const byte OPAD = (byte)0x5C;

        private readonly Md5Hash m_digest;
        private readonly byte[] m_buf;

        private Md5Hash m_ipadState;
        private Md5Hash m_opadState;

        internal Md5Hmac()
        {
            this.m_digest = new Md5Hash();
            this.m_buf = new byte[BlockLength];
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            m_digest.Reset();

            if (keyLen > BlockLength)
            {
                m_digest.Update(key, keyOff, keyLen);
                m_digest.CalculateHash(m_buf, 0);
                Arrays.Fill(m_buf, DigestSize, BlockLength, 0x00);
            }
            else
            {
                Array.Copy(key, keyOff, m_buf, 0, keyLen);
                Arrays.Fill(m_buf, keyLen, BlockLength, 0x00);
            }

            XorPad(m_buf, OPAD);

            this.m_opadState = m_digest.Copy();
            m_opadState.Update(m_buf, 0, BlockLength);

            XorPad(m_buf, OPAD ^ IPAD);

            m_digest.Update(m_buf, 0, BlockLength);
            this.m_ipadState = m_digest.Copy();

            Arrays.Fill(m_buf, 0, BlockLength, 0x00);
        }

        public void Update(byte[] input, int inOff, int length)
        {
            m_digest.Update(input, inOff, length);
        }

        public byte[] CalculateMac()
        {
            byte[] result = new byte[DigestSize];
            CalculateMac(result, 0);
            return result;
        }

        public void CalculateMac(byte[] output, int outOff)
        {
            if (m_ipadState == null)
                throw new InvalidOperationException();

            m_digest.CalculateHash(m_buf, 0);

            m_digest.Reset(m_opadState);
            m_digest.Update(m_buf, 0, DigestSize);
            m_digest.CalculateHash(output, outOff);
            Arrays.Fill(m_buf, 0, DigestSize, 0x00);

            m_digest.Reset(m_ipadState);
        }

        public int InternalBlockSize
        {
            get { return BlockLength; }
        }

        public int MacLength
        {
            get { return DigestSize; }
        }

        public void Reset()
        {
            if (m_ipadState == null)
                throw new InvalidOperationException();

            m_digest.Reset(m_ipadState);
        }

        private static void XorPad(byte[] buf, byte pad)
        {
            for (int i = 0; i < BlockLength; ++i)
            {
                buf[i] ^= pad;
            }
        }
    }
}

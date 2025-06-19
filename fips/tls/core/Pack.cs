using System;

namespace Org.BouncyCastle.Tls.Core
{
    internal sealed class Pack
    {
        private Pack()
        {
        }

        internal static byte[] Int32_To_BE(int n)
        {
            byte[] bs = new byte[4];
            Int32_To_BE(n, bs, 0);
            return bs;
        }

        internal static void Int32_To_BE(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)(n);
        }

        internal static void Int32_To_LE(int n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        internal static void Int64_To_BE(long n, byte[] bs, int off)
        {
            Int32_To_BE((int)(n >> 32), bs, off);
            Int32_To_BE((int)(n), bs, off + 4);
        }

        internal static void Int64_To_LE(long n, byte[] bs, int off)
        {
            Int32_To_LE((int)(n), bs, off);
            Int32_To_LE((int)(n >> 32), bs, off + 4);
        }

        internal static int LE_To_Int32(byte[] bs, int off)
        {
            return (int)bs[off]
                | (int)bs[off + 1] << 8
                | (int)bs[off + 2] << 16
                | (int)bs[off + 3] << 24;
        }
    }
}

using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Core
{
    internal sealed class Streams
    {
        public static void ValidateBufferArguments(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException("buffer");
            int available = buffer.Length - offset;
            if ((offset | available) < 0)
                throw new ArgumentOutOfRangeException("offset");
            int remaining = available - count;
            if ((count | remaining) < 0)
                throw new ArgumentOutOfRangeException("count");
        }

        /// <exception cref="IOException"></exception>
        internal static void WriteBufTo(MemoryStream buf, Stream output)
        {
            buf.WriteTo(output);
        }
    }
}

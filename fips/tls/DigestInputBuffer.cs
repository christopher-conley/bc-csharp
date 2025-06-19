using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    internal class DigestInputBuffer
        : MemoryStream
    {
        internal void UpdateDigest(TlsHash hash)
        {
            Core.Streams.WriteBufTo(this, new TlsHashSink(hash));
        }

        /// <exception cref="IOException"/>
        internal void CopyInputTo(Stream output)
        {
            // TODO[tls-port]
            // NOTE: Copy data since the output here may be under control of external code.
            //Streams.PipeAll(new MemoryStream(buf, 0, count), output);
            Core.Streams.WriteBufTo(this, output);
        }
    }
}

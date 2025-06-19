using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsStreamSigner
        : TlsStreamSigner
    {
        private readonly IStreamCalculator<IBlockResult> m_signer;

        internal BcTlsStreamSigner(IStreamCalculator<IBlockResult> signer)
        {
            this.m_signer = signer;
        }

        public Stream Stream
        {
            get { return m_signer.Stream; }
        }

        public byte[] GetSignature()
        {
            return BcTlsCrypto.CollectResult(m_signer);
        }
    }
}

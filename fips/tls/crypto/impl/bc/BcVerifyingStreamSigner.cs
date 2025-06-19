using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcVerifyingStreamSigner
        : TlsStreamSigner
    {
        private readonly IStreamCalculator<IBlockResult> m_signer;
        private readonly IStreamCalculator<IVerifier> m_verifier;
        private readonly TeeOutputStream m_output;

        internal BcVerifyingStreamSigner(IStreamCalculator<IBlockResult> signer, IStreamCalculator<IVerifier> verifier)
        {
            this.m_signer = signer;
            this.m_verifier = verifier;
            this.m_output = new TeeOutputStream(signer.Stream, verifier.Stream);
        }

        public Stream Stream
        {
            get { return m_output; }
        }

        public byte[] GetSignature()
        {
            byte[] signature = BcTlsCrypto.CollectResult(m_signer);

            if (!BcTlsCrypto.IsVerifiedResult(m_verifier, signature))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return signature;
        }
    }
}

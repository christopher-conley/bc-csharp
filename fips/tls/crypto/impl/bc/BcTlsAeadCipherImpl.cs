using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsAeadCipherImpl<TParameters, TAlgorithm>
        : TlsAeadCipherImpl
        where TAlgorithm : Algorithm
        where TParameters : AuthenticationParametersWithIV<TParameters, TAlgorithm>
    {
        private readonly TParameters m_parameters;
        private readonly bool m_isEncrypting;
        private readonly Func<byte[], ICryptoServiceType<IAeadCipherService>> m_keyFunc;

        private IAeadCipherService m_service;
        private IAeadCipherBuilder<TParameters> m_builder;
        private byte[] m_additionalData;

        public BcTlsAeadCipherImpl(TParameters parameters, bool isEncrypting,
            Func<byte[], ICryptoServiceType<IAeadCipherService>> keyFunc)
        {
            this.m_parameters = parameters;
            this.m_isEncrypting = isEncrypting;
            this.m_keyFunc = keyFunc;
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            byte[] keyBytes = Arrays.CopyOfRange(key, keyOff, keyOff + keyLen);
            ICryptoServiceType<IAeadCipherService> serviceType = m_keyFunc(keyBytes);
            this.m_service = CryptoServicesRegistrar.CreateService(serviceType);
        }

        public void Init(byte[] nonce, int macSize, byte[] additionalData)
        {
            TParameters algorithmDetails = m_parameters.WithIV(nonce).WithMacSize(macSize * 8);
            if (m_isEncrypting)
            {
                this.m_builder = m_service.CreateAeadEncryptorBuilder(algorithmDetails);
            }
            else 
            {
                this.m_builder = m_service.CreateAeadDecryptorBuilder(algorithmDetails);
            }
            this.m_additionalData = additionalData;
        }

        public int GetOutputSize(int inputLength)
        {
            return m_builder.GetMaxOutputSize(inputLength);
        }

        public int DoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            Buffer buffer = new Buffer(output, outputOffset);
            IAeadCipher cipher = m_builder.BuildAeadCipher(AeadUsage.AAD_FIRST, buffer);
            cipher.AadStream.Write(m_additionalData, 0, m_additionalData.Length);

            try
            {
                cipher.Stream.Write(input, inputOffset, inputLength);
                cipher.Stream.Close();
                return (int)buffer.Position;
            }
            catch (InvalidCipherTextException e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
            }
        }

        private class Buffer
            : MemoryStream
        {
            internal Buffer(byte[] buf, int off)
                : base(buf, off, buf.Length - off, true)
            {
            }

            public override void Close()
            {
            }
        }
    }
}

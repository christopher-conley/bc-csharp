using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsBlockCipherImpl<TParameters, TAlgorithm>
        : TlsBlockCipherImpl
        where TAlgorithm : Algorithm
        where TParameters : ParametersWithIV<TParameters, TAlgorithm>
    {
        private readonly int m_blockSize;
        private readonly TParameters m_parameters;
        private readonly bool m_isEncrypting;
        private readonly Func<byte[], ICryptoServiceType<IBlockCipherService>> m_keyFunc;

        private IBlockCipherService m_service;
        private IBlockCipherBuilder<TParameters> m_builder;

        internal BcTlsBlockCipherImpl(int blockSize, TParameters parameters, bool isEncrypting,
            Func<byte[], ICryptoServiceType<IBlockCipherService>> keyFunc)
        {
            this.m_blockSize = blockSize;
            this.m_parameters = parameters;
            this.m_isEncrypting = isEncrypting;
            this.m_keyFunc = keyFunc;
        }

        public int GetBlockSize()
        {
            // TODO[tls-import] Ideally we could get the block size from m_service
            return m_blockSize;
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            byte[] keyBytes = Arrays.CopyOfRange(key, keyOff, keyOff + keyLen);
            ICryptoServiceType<IBlockCipherService> serviceType = m_keyFunc(keyBytes);
            this.m_service = CryptoServicesRegistrar.CreateService(serviceType);
        }

        public void Init(byte[] iv, int ivOff, int ivLen)
        {
            byte[] ivBytes = Arrays.CopyOfRange(iv, ivOff, ivOff + ivLen);
            TParameters algorithmDetails = m_parameters.WithIV(ivBytes);
            if (m_isEncrypting)
            {
                this.m_builder = m_service.CreateBlockEncryptorBuilder(algorithmDetails);
            }
            else
            {
                this.m_builder = m_service.CreateBlockDecryptorBuilder(algorithmDetails);
            }
        }

        public int DoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            Buffer buffer = new Buffer(output, outputOffset);
            IBlockCipher cipher = m_builder.BuildBlockCipher(buffer);
            cipher.Stream.Write(input, inputOffset, inputLength);
            cipher.Stream.Close();
            return (int)buffer.Position;
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

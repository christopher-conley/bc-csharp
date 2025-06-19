using System;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Modes;
using Org.BouncyCastle.Crypto.Internal.Wrappers;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal.Fpe;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto
{
	internal class ProviderUtils
	{
		public ProviderUtils ()
		{
		}

        private static EngineUsage GetUsage(bool forEncryption, AlgorithmMode algorithmMode)
        {
            switch (algorithmMode)
            {
                case AlgorithmMode.OFB64:
                case AlgorithmMode.OFB128:
                case AlgorithmMode.CFB8:
                case AlgorithmMode.CFB64:
                case AlgorithmMode.CFB128:
                case AlgorithmMode.OpenPGPCFB:
                case AlgorithmMode.CTR:
                case AlgorithmMode.GCM:
                case AlgorithmMode.CCM:
                    return EngineUsage.ENCRYPTION;
            }

            return forEncryption ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
        }

        internal static IAeadBlockCipher CreateAeadCipher(string name, AlgorithmMode algorithmMode, IParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, bool forEncryption, IEngineProvider<Internal.IBlockCipher> cipherProvider)
        {
            Internal.IBlockCipher baseCipher = cipherProvider.CreateEngine(GetUsage(forEncryption, algorithmMode));

            switch (algorithmMode)
            {
                case AlgorithmMode.CCM:
                    return new CcmBlockCipher(baseCipher);
                case AlgorithmMode.GCM:
                    return new GcmBlockCipher(baseCipher);
                default:
                    throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
            }
        }

        internal static IBufferedCipher CreateBufferedCipher(string name, AlgorithmMode algorithmMode, IParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, bool forEncryption, IEngineProvider<Internal.IBlockCipher> cipherProvider)
		{
            Internal.IBlockCipher baseCipher = cipherProvider.CreateEngine(GetUsage(forEncryption, algorithmMode));
			Internal.IBlockCipher cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.CBC:
				cipher = new CbcBlockCipher(baseCipher);
				break;
            case AlgorithmMode.CS1:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS1, baseCipher);
            case AlgorithmMode.CS2:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS2, baseCipher);
            case AlgorithmMode.CS3:
                return new NistCtsBlockCipher(NistCtsBlockCipher.CS3, baseCipher);
            case AlgorithmMode.CFB8:
				cipher = new CfbBlockCipher (baseCipher, 8);
				break;
			case AlgorithmMode.CFB64:
				cipher = new CfbBlockCipher (baseCipher, 64);
				break;
            case AlgorithmMode.CFB128:
                cipher = new CfbBlockCipher(baseCipher, 128);
                break;
            case AlgorithmMode.OpenPGPCFB:
                cipher = new OpenPgpCfbBlockCipher(baseCipher);
                break;
            case AlgorithmMode.OFB64:
			    cipher = new OfbBlockCipher (baseCipher, 64);
			    break;
			case AlgorithmMode.OFB128:
				cipher = new OfbBlockCipher (baseCipher, 128);
				break;
            case AlgorithmMode.CTR:
                cipher = new SicBlockCipher(baseCipher);
                break;
            default:
				throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
			}

			return new BufferedBlockCipher(cipher);
		}

        internal static IBufferedCipher CreateBufferedCipher(string name, AlgorithmMode algorithmMode, Fips.FipsAes.FpeParameters parameters, bool forEncryption, IEngineProvider<Internal.IBlockCipher> cipherProvider)
        {
            Internal.IBlockCipher baseCipher = cipherProvider.CreateEngine(GetFpeUsage(algorithmMode, parameters.IsUsingInverseFunction, forEncryption));

            switch (algorithmMode)
            {
                case AlgorithmMode.FF1:
                    return new FpeCipher(new FpeFf1Engine(baseCipher));
                case AlgorithmMode.FF3_1:
                    return new FpeCipher(new FpeFf3_1Engine(baseCipher));
                default:
                    throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
            }
        }

        private static EngineUsage GetFpeUsage(AlgorithmMode algorithmMode, bool useInverse, bool forEncryption)
        {
            if (useInverse)
            {
                return algorithmMode == AlgorithmMode.FF1 ? EngineUsage.DECRYPTION : EngineUsage.DECRYPTION_REVERSE;
            }
            else
            {
                return algorithmMode == AlgorithmMode.FF1 ? EngineUsage.ENCRYPTION : EngineUsage.ENCRYPTION_REVERSE;
            }
        }

        internal static IBufferedCipher CreateBufferedCipher(string name, AlgorithmMode algorithmMode, IParameters<Algorithm> parameters, Org.BouncyCastle.Crypto.Internal.IBlockCipher baseCipher)
		{
            Internal.IBlockCipher cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.ECB:
				cipher = baseCipher;
				break;
            default:
				throw new ArgumentException("Unknown algorithm mode passed to " + name + ".Provider: " + algorithmMode);
			}

			return new BufferedBlockCipher(cipher);
		}

        private static EngineUsage GetWrapUsage(bool useInverse, bool forWrapping)
        {
            if (useInverse)
            {
                return forWrapping ? EngineUsage.DECRYPTION : EngineUsage.ENCRYPTION;
            }
            else
            {
                return forWrapping ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
            }
        }

		internal static IWrapper CreateWrapper(string name, AlgorithmMode algorithmMode, bool useInverse, bool forWrapping, IEngineProvider<Internal.IBlockCipher> baseCipherProvider)
		{
            Internal.IBlockCipher baseCipher = baseCipherProvider.CreateEngine(GetWrapUsage(useInverse, forWrapping));
			IWrapper cipher;

			switch (algorithmMode)
			{
			case AlgorithmMode.WRAP:
				cipher = new SP80038FWrapEngine(baseCipher, useInverse);
				break;
			case AlgorithmMode.WRAPPAD:
				cipher = new SP80038FWrapWithPaddingEngine(baseCipher, useInverse);
				break;
			default:
				throw new ArgumentException("Unknown wrapper algorithm passed to " + name + ".Provider: " + algorithmMode);
			}

            cipher.Init(forWrapping, null);

			return cipher;
		}

        internal static IEngineProvider<IMac> CreateMacProvider(string name, IAuthenticationParameters<IParameters<Algorithm>, Algorithm> parameters, IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> baseCipher)
        {
            switch (parameters.Algorithm.Mode)
            {
                case AlgorithmMode.CMAC:
                    return new CMacProvider(baseCipher, parameters);
                default:
                    throw new ArgumentException("Unknown MAC algorithm passed to " + name + ".Provider: " + parameters.Algorithm.Mode);
            }
        }

        internal static IEngineProvider<IMac> CreateMacProvider(string name, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters, IEngineProvider<Org.BouncyCastle.Crypto.Internal.IBlockCipher> baseCipher)
        {
            switch (parameters.Algorithm.Mode)
            {
                case AlgorithmMode.CCM:
                    return new CcmMacProvider(baseCipher, parameters);
                case AlgorithmMode.GMAC:
                    return new GMacProvider(baseCipher, parameters);
                default:
                    throw new ArgumentException("Unknown MAC algorithm passed to " + name + ".Provider: " + parameters.Algorithm.Mode);
            }
        }

        private class FpeCipher : IBufferedCipher
        {
            private readonly FpeEngine engine;
            private readonly MemoryOutputStream buf = new MemoryOutputStream();

            public FpeCipher(FpeEngine engine)
            {
                this.engine = engine;
            }

            public string AlgorithmName
            {
                get
                {
                    return engine.AlgorithmName;
                }
            }

            private byte[] processData()
            {
                byte[] data = buf.ToArray();

                this.Reset();
       
                engine.ProcessBlock(data, 0, data.Length, data, 0);
    
                return data;
            }

            public byte[] DoFinal()
            {
                return processData();
            }

            public byte[] DoFinal(byte[] input)
            {
                ProcessBytes(input);

                return processData();
            }

            public int DoFinal(byte[] output, int outOff)
            {
                byte[] rv = processData();

                Array.Copy(rv, 0, output, outOff, rv.Length);

                return rv.Length;
            }

            public int DoFinal(byte[] input, byte[] output, int outOff)
            {
                ProcessBytes(input);

                byte[] rv = processData();

                Array.Copy(rv, 0, output, outOff, rv.Length);

                return rv.Length;
            }

            public byte[] DoFinal(byte[] input, int inOff, int length)
            {
                ProcessBytes(input, inOff, length);

                return processData();
            }

            public int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
            {
                ProcessBytes(input, inOff, length);

                byte[] rv = processData();

                Array.Copy(rv, 0, output, outOff, rv.Length);

                return rv.Length;
            }

            public int GetBlockSize()
            {
                return 1;
            }

            public int GetOutputSize(int inputLen)
            {
                return (int)buf.Length + inputLen;
            }

            public int GetUpdateOutputSize(int inputLen)
            {
                return (int)buf.Length + inputLen;
            }

            public void Init(bool forEncryption, ICipherParameters parameters)
            {
                ParametersWithRandom pwr = parameters as ParametersWithRandom;
                if (pwr != null)
                {
                    parameters = pwr.Parameters;
                }
   
                engine.Init(forEncryption, parameters);
            }

            public byte[] ProcessByte(byte input)
            {
                buf.WriteByte(input);

                return null;
            }

            public int ProcessByte(byte input, byte[] output, int outOff)
            {
                buf.WriteByte(input);

                return 0;
            }

            public byte[] ProcessBytes(byte[] input)
            {
                buf.Write(input, 0, input.Length);

                return null;
            }

            public int ProcessBytes(byte[] input, byte[] output, int outOff)
            {
                buf.Write(input, 0, input.Length);

                return 0;
            }

            public byte[] ProcessBytes(byte[] input, int inOff, int length)
            {
                buf.Write(input, inOff, length);

                return null;
            }

            public int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
            {
                buf.Write(input, inOff, length);

                return 0;
            }

            public void Reset()
            {
                int end = (int)buf.Length;

                buf.Position = 0;

                buf.Write(new byte[end], 0, end);

                buf.Position = 0;
                buf.SetLength(0);
            }
        }

        private class CMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly int macSizeInBits;

            internal CMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParameters<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.macSizeInBits = parameters.MacSizeInBits;
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new CMac(baseProvider.CreateEngine(EngineUsage.ENCRYPTION), macSizeInBits);

                mac.Init(null);

                return mac;
            }
        }

        private class GMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters;

            internal GMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.parameters = parameters; 
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new GMac(new GcmBlockCipher(baseProvider.CreateEngine(EngineUsage.ENCRYPTION)), parameters.MacSizeInBits);
                mac.Init(new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return mac;
            }
        }

        private class CcmMacProvider : IEngineProvider<IMac>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> baseProvider;
            private readonly IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters;

            internal CcmMacProvider(IEngineProvider<Internal.IBlockCipher> baseProvider, IAuthenticationParametersWithIV<IParameters<Algorithm>, Algorithm> parameters)
            {
                this.baseProvider = baseProvider;
                this.parameters = parameters;
            }

            public IMac CreateEngine(EngineUsage usage)
            {
                IMac mac = new AeadCipherMac(new CcmBlockCipher(baseProvider.CreateEngine(EngineUsage.ENCRYPTION)), parameters.MacSizeInBits);
                mac.Init(new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return mac;
            }
        }
    }
}


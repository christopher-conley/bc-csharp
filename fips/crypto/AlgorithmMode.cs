
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// An enum representing all the modes available across the full algorithm set.
    /// </summary>
	public enum AlgorithmMode
	{
		NONE,
		ECB,
		CBC,
        CS1,
        CS2,
        CS3,
		CFB8,
		CFB64,
		CFB128,
		OFB64,
		OFB128,
		CTR,
		GCM,
		CCM,
        OpenPGPCFB,
		CMAC,
		GMAC,
		WRAP,
		WRAPPAD,
		OAEP,
		PKCSv1_5,
		PSS,
        X931,
		DSA,
		DDSA,
		CDH,
		HMAC,
        FF1,
        FF3_1,
		DH,
		Ed448,
		Ed25519,
		X448,
		X25519
	}

    internal class AlgorithmModeUtils
    {
        internal static bool isBlockCipherMode(Algorithm algorithm)
        {
            AlgorithmMode mode = algorithm.Mode;

            return mode == AlgorithmMode.ECB || mode == AlgorithmMode.CBC; 
        }
    }
}


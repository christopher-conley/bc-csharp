
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Internal.Agreement
{
	/**
	 * a Diffie-Hellman key agreement class.
	 * <p/>
	 * note: This is only the basic algorithm, it doesn't take advantage of
	 * long term public keys if they are available. See the DHAgreement class
	 * for a "better" implementation.
	 */
	internal class DHBasicAgreement: IBasicAgreement
	{
	    private DHPrivateKeyParameters  key;
	    private DHParameters            dhParams;

	    public void Init(ICipherParameters    param)
	    {
			DHPrivateKeyParameters  kParam = (DHPrivateKeyParameters)param;

			this.key = kParam;
			this.dhParams = key.Parameters;
	    }

	    public int GetFieldSize()
	    {
			return (key.Parameters.P.BitLength + 7) / 8;
	    }

	    /**
	     * given a short term public key from a given party calculate the next
	     * message in the agreement sequence. 
	     */
	    public BigInteger CalculateAgreement(ICipherParameters   pubKey)
	    {
			DHPublicKeyParameters   pub = (DHPublicKeyParameters)pubKey;
			DHParameters pubParams = pub.Parameters;

			if (!pubParams.G.Equals(dhParams.G) || !pubParams.P.Equals(dhParams.P))
			{
				throw new IllegalKeyException("DH public key has wrong domain parameters");
			}

			return pub.Y.ModPow(key.X, dhParams.P);
	    }
	}
}

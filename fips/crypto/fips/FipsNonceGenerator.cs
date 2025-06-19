using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Fips
{
	/**
	 * Nonce generator for use with AEAD ciphers such as GCM. The generator guarantees the sequence
	 * number cannot wrap or go backwards.
	 */
	public class FipsNonceGenerator
	{
	    private readonly byte[] baseNonce;
	    private readonly ulong counterMask;
	    private readonly int counterBytes;

	    private ulong counterValue;
	    private bool counterExhausted;

	    public FipsNonceGenerator(byte[] baseNonce, int counterBits)
	    {
			if (baseNonce == null)
			{
				throw new ArgumentNullException("'baseNonce' cannot be null");
			}
			if (baseNonce.Length < 8)
			{
				throw new ArgumentException("'baseNonce' must be at least 8 bytes");
			}
			if (counterBits < 1 || counterBits > 64)
			{
				throw new ArgumentException("'counterBits' must be from 1 to 64 bits");
			}

			if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
			{
				if (baseNonce.Length < 12)
				{
				throw new ArgumentException("Approved mode requires 'baseNonce' of at least 12 bytes");
				}
				if (counterBits < 32)
				{
				throw new ArgumentException("Approved mode requires 'counterBits' of at least 32 bits");
				}
			}

			this.baseNonce = Arrays.Clone(baseNonce);
			this.counterMask = 0xffffffffffffffffUL >> (64 - counterBits);
			this.counterBytes = (counterBits + 7) / 8;

			this.counterValue = 0;
			this.counterExhausted = false;
	    }

	    public void GenerateNonce(byte[] nonce)
	    {
			if (baseNonce.Length != nonce.Length)
			{
				throw new ArgumentException("'nonce' length must match the base nonce length (" + baseNonce.Length + " bytes)");
			}
			if (counterExhausted)
			{
				throw new InvalidOperationException("TLS nonce generator exhausted");
			}

			Array.Copy(baseNonce, nonce, baseNonce.Length);
			xorCounter(nonce, baseNonce.Length - counterBytes);

			counterExhausted |= ((++counterValue & counterMask) == 0);
	    }

	    private void xorCounter(byte[] buf, int off)
	    {
			for (int i = 0; i < counterBytes; ++i)
			{
				buf[off + i] ^= (byte)(counterValue >> ((counterBytes - 1 - i) * 8));
			}
	    }
	}
}

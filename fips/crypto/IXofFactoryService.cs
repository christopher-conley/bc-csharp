
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for keyed-XoF factory objects.
    /// </summary>
    public interface IXofFactoryService
    {
        /// <summary>
        /// Create an XoF factory configured using the algorithmDetails parameter.
        /// </summary>
        /// <typeparam name="A">The parameter type associated with algorithmDetails</typeparam>
        /// <param name="algorithmDetails">The configuration parameters for the returned XoF factory.</param>
        /// <returns>A new MAC factory.</returns>
        IXofFactory<A> CreateXofFactory<A>(A algorithmDetails) where A : IAuthenticationParameters<A, Algorithm>;
    }
}

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    public interface IClonableSelector<TSelect>:ISelector<TSelect>
    {
        ISelector<TSelect> Clone();
    }
}

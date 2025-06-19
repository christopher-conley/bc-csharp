using System;
using System.Collections.Generic;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
    public class PkixCrlUtilities
    {
        public virtual ISet<X509Crl> FindCrls(ISelector<X509Crl> crlselect, PkixParameters paramsPkix,
            DateTime currentDate)
        {
            ISet initialSet = new HashSet();

            // get complete CRL(s)
            try
            {
                initialSet.AddAll(FindCrls(crlselect, paramsPkix.GetCrlStores()));
               // initialSet.AddAll(FindCrls(crlselect, paramsPkix.GetStores()));
            }
            catch (Exception e)
            {
                throw new Exception("Exception obtaining complete CRLs.", e);
            }

            ISet<X509Crl> finalSet = new HashSet<X509Crl>();
            DateTime validityDate = currentDate;

            if (paramsPkix.Date != null)
            {
                validityDate = paramsPkix.Date.Value;
            }

            // TODO this feels uncomfortable type checking to a specific selector type.
            // TODO perhaps move logic into the selector if that is possible.


            if (crlselect is ICheckingCertificate)
            {
                ICheckingCertificate checkingCertificate = (ICheckingCertificate)crlselect;
                // based on RFC 5280 6.3.3
                foreach (X509Crl crl in initialSet)
                {
                    if (crl.NextUpdate.Value.CompareTo(validityDate) > 0)
                    {
                        X509Certificate cert = checkingCertificate.CertificateChecking;

                        if (cert != null)
                        {
                            if (crl.ThisUpdate.CompareTo(cert.NotAfter) < 0)
                            {
                                finalSet.Add(crl);
                            }
                        }
                        else
                        {
                            finalSet.Add(crl);
                        }
                    }
                }
            }

            return finalSet;
            
        }

        public virtual ISet FindCrls(ISelector<X509Crl> crlselect, PkixParameters paramsPkix)
        {
            ISet completeSet = new HashSet();

            // get complete CRL(s)
            try
            {
                completeSet.AddAll(FindCrls(crlselect, paramsPkix.GetCrlStores()));
            }
            catch (Exception e)
            {
                throw new Exception("Exception obtaining complete CRLs.", e);
            }

            return completeSet;
        }

        /// <summary>
        /// crl checking
        /// Return a Collection of all CRLs found in the X509Store's that are
        /// matching the crlSelect criteriums.
        /// </summary>
        /// <param name="crlSelect">a {@link X509CRLStoreSelector} object that will be used
        /// to select the CRLs</param>
        /// <param name="crlStores">a List containing only {@link org.bouncycastle.x509.X509Store
        /// X509Store} objects. These are used to search for CRLs</param>
        /// <returns>a Collection of all found {@link X509CRL X509CRL} objects. May be
        /// empty but never <code>null</code>.
        /// </returns>
        private ICollection<X509Crl> FindCrls(ISelector<X509Crl> crlSelect, ICollection<IStore<X509Crl>> crlStores)
        {
            HashSet<X509Crl> crls = new HashSet<X509Crl>();

            Exception lastException = null;
            bool foundValidStore = false;

            foreach (IStore<X509Crl> store in crlStores)
            {
                try
                {
                    foreach (X509Crl x509Crl in store.GetMatches(crlSelect))
                    {
                        crls.Add(x509Crl);
                    }

                    foundValidStore = true;
                }
                catch (Exception e)
                {
                    // TODO needs a rethink and need to figure out which exceptions are being thrown.
                    lastException = new Exception("Exception searching in X.509 CRL store.", e);
                }
            }

            if (!foundValidStore && lastException != null)
                throw lastException;

            return crls;
        }
    }
}

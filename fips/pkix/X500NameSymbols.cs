using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pkix
{
    public class X500NameSymbols
    {
        /**
       * country code - StringType(SIZE(2))
       */
        public static readonly DerObjectIdentifier C = new DerObjectIdentifier("2.5.4.6");

        /**
        * organization - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier O = new DerObjectIdentifier("2.5.4.10");

        /**
        * organizational unit name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier OU = new DerObjectIdentifier("2.5.4.11");

        /**
        * Title
        */
        public static readonly DerObjectIdentifier T = new DerObjectIdentifier("2.5.4.12");

        /**
        * common name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier CN = new DerObjectIdentifier("2.5.4.3");

        /**
        * street - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier Street = new DerObjectIdentifier("2.5.4.9");

        /**
        * device serial number name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier SerialNumber = new DerObjectIdentifier("2.5.4.5");

        /**
        * locality name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier L = new DerObjectIdentifier("2.5.4.7");

        /**
        * state, or province name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier ST = new DerObjectIdentifier("2.5.4.8");

        /**
        * Naming attributes of type X520name
        */
        public static readonly DerObjectIdentifier Surname = new DerObjectIdentifier("2.5.4.4");
        public static readonly DerObjectIdentifier GivenName = new DerObjectIdentifier("2.5.4.42");
        public static readonly DerObjectIdentifier Initials = new DerObjectIdentifier("2.5.4.43");
        public static readonly DerObjectIdentifier Generation = new DerObjectIdentifier("2.5.4.44");
        public static readonly DerObjectIdentifier UniqueIdentifier = new DerObjectIdentifier("2.5.4.45");

        /**
         * businessCategory - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier BusinessCategory = new DerObjectIdentifier(
                                                                       "2.5.4.15");

        /**
         * postalCode - DirectoryString(SIZE(1..40)
         */
        public static readonly DerObjectIdentifier PostalCode = new DerObjectIdentifier(
                                                                 "2.5.4.17");

        /**
         * dnQualifier - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier DnQualifier = new DerObjectIdentifier(
                                                         "2.5.4.46");

        /**
         * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier Pseudonym = new DerObjectIdentifier(
                                                                "2.5.4.65");

        /**
         * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
         */
        public static readonly DerObjectIdentifier DateOfBirth = new DerObjectIdentifier(
                                                                  "1.3.6.1.5.5.7.9.1");

        /**
         * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier PlaceOfBirth = new DerObjectIdentifier(
                                                                   "1.3.6.1.5.5.7.9.2");

        /**
         * RFC 3039 DateOfBirth - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
         */
        public static readonly DerObjectIdentifier Gender = new DerObjectIdentifier(
                                                                   "1.3.6.1.5.5.7.9.3");

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier CountryOfCitizenship = new DerObjectIdentifier(
                                                                           "1.3.6.1.5.5.7.9.4");

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier CountryOfResidence = new DerObjectIdentifier(
                                                                         "1.3.6.1.5.5.7.9.5");

        /**s
         * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier NameAtBirth = new DerObjectIdentifier("1.3.36.8.3.14");

        /**
         * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
         * DirectoryString(SIZE(1..30))
         */
        public static readonly DerObjectIdentifier PostalAddress = new DerObjectIdentifier("2.5.4.16");

        /**
         * RFC 2256 dmdName
         */
        public static readonly DerObjectIdentifier DmdName = new DerObjectIdentifier("2.5.4.54");

        /**
         * id-at-telephoneNumber
         */
        public static readonly DerObjectIdentifier TelephoneNumber = X509ObjectIdentifiers.id_at_telephoneNumber;

        /**
         * id-at-organizationIdentifier
         */
        public static readonly DerObjectIdentifier OrganizationIdentifier = new DerObjectIdentifier("2.5.4.97"); //X509ObjectIdentifiers.id_at_organizationIdentifier;

        /**
         * id-at-name
         */
        public static readonly DerObjectIdentifier Name = X509ObjectIdentifiers.id_at_name;

        /**
        * Email address (RSA PKCS#9 extension) - IA5String.
        * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.</p>
        */
        public static readonly DerObjectIdentifier EmailAddress = PkcsObjectIdentifiers.Pkcs9AtEmailAddress;

        /**
        * more from PKCS#9
        */
        public static readonly DerObjectIdentifier UnstructuredName = PkcsObjectIdentifiers.Pkcs9AtUnstructuredName;
        public static readonly DerObjectIdentifier UnstructuredAddress = PkcsObjectIdentifiers.Pkcs9AtUnstructuredAddress;

        /**
        * email address in Verisign certificates
        */
        public static readonly DerObjectIdentifier E = EmailAddress;

        /*
        * others...
        */
        public static readonly DerObjectIdentifier DC = new DerObjectIdentifier("0.9.2342.19200300.100.1.25");

        /**
        * LDAP User id.
        */
        public static readonly DerObjectIdentifier UID = new DerObjectIdentifier("0.9.2342.19200300.100.1.1");

        /**
         * default look up table translating OID values into their common symbols following
         * the convention in RFC 2253 with a few extras
         */
        public static readonly IDictionary DefaultSymbols = Platform.CreateHashtable();

        /**
         * look up table translating OID values into their common symbols following the convention in RFC 2253
         */
        public static readonly IDictionary<DerObjectIdentifier, string> RFC2253Symbols =
            new Dictionary<DerObjectIdentifier, string>();

        /**
         * look up table translating OID values into their common symbols following the convention in RFC 1779
         *
         */
        public static readonly IDictionary RFC1779Symbols = Platform.CreateHashtable();

        /**
        * look up table translating common symbols into their OIDS.
        */
        public static readonly IDictionary<DerObjectIdentifier,string> DefaultLookup = new Dictionary<DerObjectIdentifier, string>();
        public static readonly IDictionary<string, DerObjectIdentifier> DefaultLookupReverse = new Dictionary<string, DerObjectIdentifier>();


        static X500NameSymbols()
        {
            DefaultSymbols.Add(C, "C");
            DefaultSymbols.Add(O, "O");
            DefaultSymbols.Add(T, "T");
            DefaultSymbols.Add(OU, "OU");
            DefaultSymbols.Add(CN, "CN");
            DefaultSymbols.Add(L, "L");
            DefaultSymbols.Add(ST, "ST");
            DefaultSymbols.Add(SerialNumber, "SERIALNUMBER");
            DefaultSymbols.Add(EmailAddress, "E");
            DefaultSymbols.Add(DC, "DC");
            DefaultSymbols.Add(UID, "UID");
            DefaultSymbols.Add(Street, "STREET");
            DefaultSymbols.Add(Surname, "SURNAME");
            DefaultSymbols.Add(GivenName, "GIVENNAME");
            DefaultSymbols.Add(Initials, "INITIALS");
            DefaultSymbols.Add(Generation, "GENERATION");
            DefaultSymbols.Add(UnstructuredAddress, "unstructuredAddress");
            DefaultSymbols.Add(UnstructuredName, "unstructuredName");
            DefaultSymbols.Add(UniqueIdentifier, "UniqueIdentifier");
            DefaultSymbols.Add(DnQualifier, "DN");
            DefaultSymbols.Add(Pseudonym, "Pseudonym");
            DefaultSymbols.Add(PostalAddress, "PostalAddress");
            DefaultSymbols.Add(NameAtBirth, "NameAtBirth");
            DefaultSymbols.Add(CountryOfCitizenship, "CountryOfCitizenship");
            DefaultSymbols.Add(CountryOfResidence, "CountryOfResidence");
            DefaultSymbols.Add(Gender, "Gender");
            DefaultSymbols.Add(PlaceOfBirth, "PlaceOfBirth");
            DefaultSymbols.Add(DateOfBirth, "DateOfBirth");
            DefaultSymbols.Add(PostalCode, "PostalCode");
            DefaultSymbols.Add(BusinessCategory, "BusinessCategory");
            DefaultSymbols.Add(TelephoneNumber, "TelephoneNumber");

            RFC2253Symbols.Add(C, "C");
            RFC2253Symbols.Add(O, "O");
            RFC2253Symbols.Add(OU, "OU");
            RFC2253Symbols.Add(CN, "CN");
            RFC2253Symbols.Add(L, "L");
            RFC2253Symbols.Add(ST, "ST");
            RFC2253Symbols.Add(Street, "STREET");
            RFC2253Symbols.Add(DC, "DC");
            RFC2253Symbols.Add(UID, "UID");

            RFC1779Symbols.Add(C, "C");
            RFC1779Symbols.Add(O, "O");
            RFC1779Symbols.Add(OU, "OU");
            RFC1779Symbols.Add(CN, "CN");
            RFC1779Symbols.Add(L, "L");
            RFC1779Symbols.Add(ST, "ST");
            RFC1779Symbols.Add(Street, "STREET");

            DefaultLookupReverse.Add("c", C);
            DefaultLookupReverse.Add("o", O);
            DefaultLookupReverse.Add("t", T);
            DefaultLookupReverse.Add("ou", OU);
            DefaultLookupReverse.Add("cn", CN);
            DefaultLookupReverse.Add("l", L);
            DefaultLookupReverse.Add("st", ST);
            DefaultLookupReverse.Add("serialnumber", SerialNumber);
            DefaultLookupReverse.Add("street", Street);
            DefaultLookupReverse.Add("emailaddress", E);
            DefaultLookupReverse.Add("dc", DC);
            DefaultLookupReverse.Add("e", E);
            DefaultLookupReverse.Add("uid", UID);
            DefaultLookupReverse.Add("surname", Surname);
            DefaultLookupReverse.Add("givenname", GivenName);
            DefaultLookupReverse.Add("initials", Initials);
            DefaultLookupReverse.Add("generation", Generation);
            DefaultLookupReverse.Add("unstructuredaddress", UnstructuredAddress);
            DefaultLookupReverse.Add("unstructuredname", UnstructuredName);
            DefaultLookupReverse.Add("uniqueidentifier", UniqueIdentifier);
            DefaultLookupReverse.Add("dn", DnQualifier);
            DefaultLookupReverse.Add("pseudonym", Pseudonym);
            DefaultLookupReverse.Add("postaladdress", PostalAddress);
            DefaultLookupReverse.Add("nameofbirth", NameAtBirth);
            DefaultLookupReverse.Add("countryofcitizenship", CountryOfCitizenship);
            DefaultLookupReverse.Add("countryofresidence", CountryOfResidence);
            DefaultLookupReverse.Add("gender", Gender);
            DefaultLookupReverse.Add("placeofbirth", PlaceOfBirth);
            DefaultLookupReverse.Add("dateofbirth", DateOfBirth);
            DefaultLookupReverse.Add("postalcode", PostalCode);
            DefaultLookupReverse.Add("businesscategory", BusinessCategory);
            DefaultLookupReverse.Add("telephonenumber", TelephoneNumber);
        }
    }
}

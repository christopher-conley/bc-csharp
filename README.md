# The Bouncy Castle Cryptography Library (with FIPS) For .NET

## Important Note: The purpose of this fork

This repo contains sources tracking the current version of the Bouncy Castle Cryptography library (available in the non-default [`master`](https://github.com/christopher-conley/bc-csharp/tree/master) branch), as well as the FIPS version and an accompanying `csproj` file in the [`fips`](https://github.com/christopher-conley/bc-csharp/tree/HEAD/fips) subdirectory.

For some reason, the FIPS sources are not tracked (or available at all) in [the official BouncyCastle git repository](https://github.com/bcgit/bc-csharp), but they *are* available at [their website](https://www.bouncycastle.org/) if you look hard enough and sacrifice the correct number of goats. The XML documentation, debug files, and source code obtainable on their website comes in several disparate zip files and contains no git history. The purpose of this fork is to make those sources easily-accessible and compilable. These sources were last retrieved on 2025-06-19 for the latest-available version (`1.0.2`) of the Bouncy Castle Cryptography library.

The FIPS source code has been consolidated/repatriated into a single source directory tree ([`fips`](https://github.com/christopher-conley/bc-csharp/tree/HEAD/fips)), has been given its own independent Project file (`BouncyCastle.Crypto.FIPS`) within the main solution file, and is configured to produce a single assembly instead of several independent assemblies; the original source code itself, though, remains completely unaltered. The source files used to construct the [`fips`](https://github.com/christopher-conley/bc-csharp/tree/HEAD/fips) directory were last retrieved on 2025-06-19 and are available in the [`fips_original_source`](https://github.com/christopher-conley/bc-csharp/tree/HEAD/fips_original_source) directory.

Please note that the FIPS version is a separate code base and separate assembly from the non-FIPS version, and it has several incompatibilities with the non-FIPS version. The FIPS version is designed to meet the requirements of the Federal Information Processing Standards (FIPS) as defined and established by the National Institute of Standards and Technology ([NIST](https://www.nist.gov)) in the publication "Security Requirements for Cryptographic Modules", detailed in [FIPS 140-2](https://csrc.nist.gov/pubs/fips/140-2/upd2/final) and [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final). Although usable anywhere, it is intended for use in environments that require FIPS compliance. If you don't know what FIPS is, you probably don't need this.

---
## Original README is as follows:

The Bouncy Castle Cryptography library is a .NET implementation of cryptographic algorithms and protocols. It was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

In addition to providing basic cryptography algorithms, the package also provides support for CMS, OpenPGP, (D)TLS, TSP, X.509 certificate generation and more. The package also includes implementations of the following NIST Post-Quantum Cryptography Standardization algorithms: ML-DSA, ML-KEM, SLH-DSA, Falcon, Classic McEliece, FrodoKEM, NTRU, NTRU Prime, Picnic, Saber, and BIKE. These should all be considered EXPERIMENTAL and subject to change or removal.

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/csharp/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a [support contract](https://www.keyfactor.com/platform/bouncy-castle-support/).

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). This software includes a modified Bzip2 library, which is licensed under the [Apache Software License, Version 2.0](http://www.apache.org/licenses/). 

~~**Note**: This source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please visit us [here](https://www.bouncycastle.org/fips-csharp) or contact us directly at [office@bouncycastle.org](mailto:office@bouncycastle.org).~~

## Installing BouncyCastle

You should install [BouncyCastle with NuGet:](https://www.nuget.org/packages/BouncyCastle.Cryptography)

    Install-Package BouncyCastle.Cryptography

Or via the .NET Core command line interface:

    dotnet add package BouncyCastle.Cryptography

Either commands, from Package Manager Console or .NET Core CLI, will download and install BouncyCastle.Cryptography.

## Mailing Lists

To subscribe use the link below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body).

*   [announce-crypto-csharp-request@bouncycastle.org](mailto:announce-crypto-csharp-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.

Note that the former dev-crypto-csharp mailing list has been discontinued. Please use https://github.com/bcgit/bc-csharp/discussions instead for usage questions, enhancement requests, etc.

## Feedback 

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org). If you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues on [github](https://github.com/bcgit/bc-csharp), or via [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org) if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!

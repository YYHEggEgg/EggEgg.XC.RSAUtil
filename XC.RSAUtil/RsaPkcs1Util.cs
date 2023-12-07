using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace XC.RSAUtil
{
    /// <summary>
    /// RSA pkcs1 format key helper class
    /// Author:Zhiqiang Li
    /// </summary>
    public class RsaPkcs1Util : RSAUtilBase
    {
        /// <summary>
        /// The class initializer.
        /// </summary>
        /// <param name="publicKey">The public key can be infered from private key.</param>
        /// <param name="privateKey">If not given, this instance won't support private key features.</param>
        /// <exception cref="ArgumentException">Neither <paramref name="publicKey"/> nor <paramref name="privateKey"/> has been given.</exception>
        public RsaPkcs1Util(string? privateKey = null, string? publicKey = null)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentException("Public and private keys must not be empty at the same time");
            }

            if (!string.IsNullOrEmpty(privateKey))
            {
                PrivateRsa = RSA.Create();
                var priRsap = CreateRsapFromPrivateKey(privateKey);
                PrivateRsa.KeySize = CalculateKeyLength(priRsap.Modulus);
                PrivateRsa.ImportParameters(priRsap);

                if (string.IsNullOrEmpty(publicKey))
                {
                    PublicRsa = RSA.Create();
                    var pubRsap = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.KeySize = CalculateKeyLength(pubRsap.Modulus);
                    PublicRsa.ImportParameters(pubRsap);
                }

            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = RSA.Create();
                var pubRsap = CreateRsapFromPublicKey(publicKey);
                PublicRsa.KeySize = CalculateKeyLength(pubRsap.Modulus);
                PublicRsa.ImportParameters(CreateRsapFromPublicKey(publicKey));
            }
        }
        /// <summary>
        /// Create an RSA parameter based on the xml format public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        protected sealed override RSAParameters CreateRsapFromPublicKey(string publicKey)
        {
            publicKey = RsaPemFormatHelper.Pkcs1PublicKeyFormat(publicKey);

            PemReader pr = new PemReader(new StringReader(publicKey));
            var obj = pr.ReadObject();
            if (!(obj is RsaKeyParameters rsaKey))
            {
                throw new ArgumentException("Public key format is incorrect", nameof(publicKey));
            }
            var rsap = new RSAParameters
            {
                Modulus = rsaKey.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKey.Exponent.ToByteArrayUnsigned()
            };
            return rsap;
        }

        /// <summary>
        /// Create an RSA parameter based on the xml format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));
            if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            {
                throw new ArgumentException("Private key format is incorrect", privateKey);
            }
            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters =
                (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));
            var rsap = new RSAParameters
            {
                Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned(),
                Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned(),
                DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned(),
                D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()
            };

            return rsap;
        }
    }
}
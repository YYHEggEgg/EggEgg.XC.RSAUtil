using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace XC.RSAUtil
{
    /// <summary>
    ///  Rsa Key Generator
    /// Author:Zhiqiang Li
    /// </summary>
    public partial class RsaKeyGenerator
    {
        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static KeyResult XmlKey(int keySize)
        {
            RSA rsa = RSA.Create();
            rsa.KeySize = keySize;
            var rsap = rsa.ExportParameters(true);
            KeyResult res = new KeyResult();
            if (rsap.Modulus == null || rsap.Exponent == null || rsap.P == null || rsap.Q == null
                || rsap.DP == null || rsap.DQ == null || rsap.InverseQ == null || rsap.D == null)
                throw new Exception($"Generate key failed!");

            XElement privatElement = new XElement("RSAKeyValue");
            //Modulus
            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
            //Exponent
            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));
            //P
            XElement prip = new XElement("P", Convert.ToBase64String(rsap.P));
            //Q
            XElement priq = new XElement("Q", Convert.ToBase64String(rsap.Q));
            //DP
            XElement pridp = new XElement("DP", Convert.ToBase64String(rsap.DP));
            //DQ
            XElement pridq = new XElement("DQ", Convert.ToBase64String(rsap.DQ));
            //InverseQ
            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsap.InverseQ));
            //D
            XElement prid = new XElement("D", Convert.ToBase64String(rsap.D));

            privatElement.Add(primodulus);
            privatElement.Add(priexponent);
            privatElement.Add(prip);
            privatElement.Add(priq);
            privatElement.Add(pridp);
            privatElement.Add(pridq);
            privatElement.Add(priinverseQ);
            privatElement.Add(prid);

            //添加私钥
            res.privateKey = privatElement.ToString();


            XElement publicElement = new XElement("RSAKeyValue");
            //Modulus
            XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
            //Exponent
            XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));

            publicElement.Add(pubmodulus);
            publicElement.Add(pubexponent);

            //添加公钥
            res.publicKey = publicElement.ToString();

            return res;
        }

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="format">Whether the return is standard pem file format. If false, the method will return the PEM base64 string.</param>
        /// <returns></returns>
        public static KeyResult Pkcs1Key(int keySize, bool format = true) => PemKeyGenAttempt(RsaKeyPadding.Pkcs1, keySize, format);

        private static KeyResult Pkcs1KeyCore(int keySize)
        {
            KeyResult res = new KeyResult();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            pWrt.WriteObject(keyPair.Private);
            pWrt.Writer.Close();
            res.privateKey = sw.ToString();

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
            pWrtpub.WriteObject(keyPair.Public);
            pWrtpub.Writer.Close();
            string publicKey = swpub.ToString();
            publicKey = RsaKeyConvert.PublicKeyPkcs8ToPkcs1(publicKey);
            res.publicKey = publicKey;

            return res;
        }

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="format">Whether the return is standard pem file format. If false, the method will return the PEM base64 string.</param>
        /// <returns></returns>
        public static KeyResult Pkcs8Key(int keySize, bool format = true) => PemKeyGenAttempt(RsaKeyPadding.Pkcs8, keySize, format);

        private static KeyResult Pkcs8KeyCore(int keySize)
        {
            KeyResult res = new KeyResult();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter swpri = new StringWriter();
            PemWriter pWrtpri = new PemWriter(swpri);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(keyPair.Private);
            pWrtpri.WriteObject(pkcs8);
            pWrtpri.Writer.Close();
            res.privateKey = swpri.ToString();

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
            pWrtpub.WriteObject(keyPair.Public);
            pWrtpub.Writer.Close();
            res.publicKey = swpub.ToString();

            return res;
        }

        public struct KeyResult
        {
            public string publicKey;
            public string privateKey;
        }
    }
}

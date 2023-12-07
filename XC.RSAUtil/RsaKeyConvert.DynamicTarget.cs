using System;

namespace XC.RSAUtil
{
    [Flags]
    public enum RsaKeyType
    {
        None = 0,
        Xml = 2 << 0,
        Pkcs1 = 2 << 1,
        Pkcs8 = 2 << 2,
        Private = 2 << 3,
        Public = 2 << 4,
    }

    public partial class RsaKeyConvert
    {
        private static void ValidateTransferRSAKeyTypes(RsaKeyType inputKeyType, RsaKeyType outputKeyType)
        {
            inputKeyType.ValidateRsaKeyType(nameof(inputKeyType));
            outputKeyType.ValidateRsaKeyType(nameof(outputKeyType));

            if (((inputKeyType & RsaKeyType.Public) != 0) && ((outputKeyType & RsaKeyType.Private) != 0))
            {
                throw new ArgumentException($"Cannot convert public key to private key.");
            }

            if ((((inputKeyType & RsaKeyType.Private) != 0) && ((outputKeyType & RsaKeyType.Private) != 0)) ||
                (((inputKeyType & RsaKeyType.Public) != 0) && ((outputKeyType & RsaKeyType.Public) != 0)))
            {
                if ((((inputKeyType & RsaKeyType.Xml) != 0) && ((outputKeyType & RsaKeyType.Xml) != 0)) ||
                    (((inputKeyType & RsaKeyType.Pkcs1) != 0) && ((outputKeyType & RsaKeyType.Pkcs1) != 0)) ||
                    (((inputKeyType & RsaKeyType.Pkcs8) != 0) && ((outputKeyType & RsaKeyType.Pkcs8) != 0))
                )
                {
                    throw new ArgumentException($"Input and output key cannot be the same padding when input and output are both private/public keys.");
                }
            }
        }

        /// <summary>
        /// Select convert type yourself.
        /// </summary>
        public static string Format(string rsakey, RsaKeyType inputKeyType, RsaKeyType outputKeyType)
        {
            ValidateTransferRSAKeyTypes(inputKeyType, outputKeyType);

            string? res = null;

            if ((inputKeyType & RsaKeyType.Xml) != 0)
            {
                if ((inputKeyType & RsaKeyType.Private) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Pkcs1) != 0)
                    {
                        res = PrivateKeyXmlToPkcs1(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs1ToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs8) != 0)
                    {
                        res = PrivateKeyXmlToPkcs8(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs8ToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Xml) != 0)
                    {
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyXmlToPublic(rsakey);
                    }
                }
                else if ((inputKeyType & RsaKeyType.Public) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Pkcs1) != 0)
                    {
                        res = PublicKeyXmlToPkcs1(rsakey);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs8) != 0)
                    {
                        res = PublicKeyXmlToPkcs8(rsakey);
                    }
                }
            }
            else if ((inputKeyType & RsaKeyType.Pkcs1) != 0)
            {
                if ((inputKeyType & RsaKeyType.Private) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Xml) != 0)
                    {
                        res = PrivateKeyPkcs1ToXml(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyXmlToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs8) != 0)
                    {
                        res = PrivateKeyPkcs1ToPkcs8(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs1ToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs1) != 0)
                    {
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs1ToPublic(rsakey);
                    }
                }
                else if ((inputKeyType & RsaKeyType.Public) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Xml) != 0)
                    {
                        res = PublicKeyPkcs1ToXml(rsakey);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs8) != 0)
                    {
                        res = PublicKeyPkcs1ToPkcs8(rsakey);
                    }
                }
            }
            else if ((inputKeyType & RsaKeyType.Pkcs8) != 0)
            {
                if ((inputKeyType & RsaKeyType.Private) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Xml) != 0)
                    {
                        res = PrivateKeyPkcs8ToXml(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyXmlToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs1) != 0)
                    {
                        res = PrivateKeyPkcs8ToPkcs1(rsakey);
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs1ToPublic(res);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs8) != 0)
                    {
                        if ((outputKeyType & RsaKeyType.Public) != 0)
                            res = PrivateKeyPkcs8ToPublic(rsakey);
                    }
                }
                else if ((inputKeyType & RsaKeyType.Public) != 0)
                {
                    if ((outputKeyType & RsaKeyType.Xml) != 0)
                    {
                        res = PublicKeyPkcs8ToXml(rsakey);
                    }
                    else if ((outputKeyType & RsaKeyType.Pkcs1) != 0)
                    {
                        res = PublicKeyPkcs8ToPkcs1(rsakey);
                    }
                }
            }
            return res ?? throw new InvalidOperationException("Unknown format condition: please report to EggEgg.XC.RSAUtil.");
        }
    }

    public static class RsaKeyTypeExtension_HIFBHDWFWES
    {
        public static void ValidateRsaKeyType(this RsaKeyType keyType, string? paramName = null)
        {
            if (keyType == RsaKeyType.None)
            {
                throw new ArgumentException("A RSA Key with no flags is invalid.");
            }
            if (((keyType & RsaKeyType.Private) != 0) && ((keyType & RsaKeyType.Public) != 0))
            {
                throw new ArgumentException("Cannot provide a key that is both private and public.");
            }
            if ((((keyType & RsaKeyType.Xml) != 0) && ((keyType & RsaKeyType.Pkcs1) != 0)) ||
                (((keyType & RsaKeyType.Xml) != 0) && ((keyType & RsaKeyType.Pkcs8) != 0)) ||
                (((keyType & RsaKeyType.Pkcs1) != 0) && ((keyType & RsaKeyType.Pkcs8) != 0))
            )
            {
                throw new ArgumentException("Cannot provide a key that have multiple paddings.");
            }
            if (((keyType & RsaKeyType.Private) == 0) && ((keyType & RsaKeyType.Public) == 0))
            {
                throw new ArgumentException("RSA Key should be either private or public.", paramName);
            }
            if (((keyType & RsaKeyType.Xml) == 0) &&
                ((keyType & RsaKeyType.Pkcs1) == 0) &&
                ((keyType & RsaKeyType.Pkcs8) == 0)
            )
            {
                throw new ArgumentException("RSA key should have one padding.", paramName);
            }
        }
    }
}
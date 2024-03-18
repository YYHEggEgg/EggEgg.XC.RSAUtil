using System;
using System.Text;

namespace XC.RSAUtil
{
    public partial class RsaKeyConvert
    {
        private static void ValidateTransferRSAKeyTypes(RsaKeyFeature inputKeyType, RsaKeyFeature outputKeyType)
        {
            inputKeyType.Validate(nameof(inputKeyType));
            outputKeyType.Validate(nameof(outputKeyType));

            if (!inputKeyType.IsPrivate && outputKeyType.IsPrivate)
            {
                throw new ArgumentException($"Cannot convert public key to private key.");
            }

            if (inputKeyType.IsPrivate == outputKeyType.IsPrivate &&
                inputKeyType.Padding == outputKeyType.Padding &&
                inputKeyType.Format == outputKeyType.Format)            {
                throw new ArgumentException($"Input and output key cannot be the same padding and format when input and output are both private/public keys.");
            }
        }

        /// <summary>
        /// Select convert type yourself.
        /// </summary>
        public static string Format(string rsakey, RsaKeyFeature inputKeyType, RsaKeyFeature outputKeyType)
        {
            ValidateTransferRSAKeyTypes(inputKeyType, outputKeyType);

            string? res = null;

            switch (inputKeyType.Padding)
            {
                case RsaKeyPadding.Xml:
                    if (inputKeyType.IsPrivate)
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Pkcs1:
                                res = PrivateKeyXmlToPkcs1(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs1ToPublic(res);
                                break;
                            case RsaKeyPadding.Pkcs8:
                                res = PrivateKeyXmlToPkcs8(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs8ToPublic(res);
                                break;
                            case RsaKeyPadding.Xml:
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyXmlToPublic(rsakey);
                                break;
                        }
                    }
                    else
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Pkcs1:
                                res = PublicKeyXmlToPkcs1(rsakey);
                                break;
                            case RsaKeyPadding.Pkcs8:
                                res = PublicKeyXmlToPkcs8(rsakey); 
                                break;
                        }
                    }
                    break;
                case RsaKeyPadding.Pkcs1:
                    if (inputKeyType.IsPrivate)
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Xml:
                                res = PrivateKeyPkcs1ToXml(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyXmlToPublic(res);
                                break;
                            case RsaKeyPadding.Pkcs8:
                                res = PrivateKeyPkcs1ToPkcs8(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs1ToPublic(res);
                                break;
                            case RsaKeyPadding.Pkcs1:
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs1ToPublic(rsakey);
                                break;
                        }
                    }
                    else
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Xml:
                                res = PublicKeyPkcs1ToXml(rsakey);
                                break;
                            case RsaKeyPadding.Pkcs8:
                                res = PublicKeyPkcs1ToPkcs8(rsakey);
                                break;
                        }
                    }
                    break;
                case RsaKeyPadding.Pkcs8:
                    if (inputKeyType.IsPrivate)
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Xml:
                                res = PrivateKeyPkcs8ToXml(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyXmlToPublic(res);
                                break;
                            case RsaKeyPadding.Pkcs1:
                                res = PrivateKeyPkcs8ToPkcs1(rsakey);
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs1ToPublic(res);
                                break;
                            case RsaKeyPadding.Pkcs8:
                                if (!outputKeyType.IsPrivate)
                                    res = PrivateKeyPkcs8ToPublic(rsakey);
                                break;
                        }
                    }
                    else
                    {
                        switch (outputKeyType.Padding)
                        {
                            case RsaKeyPadding.Xml:
                                res = PublicKeyPkcs8ToXml(rsakey);
                                break;
                            case RsaKeyPadding.Pkcs1:
                                res = PublicKeyPkcs8ToPkcs1(rsakey);
                                break;
                        }
                    }
                    break;
            }

            
            return res ?? throw new InvalidOperationException("Unknown format condition: please report to EggEgg.XC.RSAUtil.");
        }

        public static byte[] Format(byte[] rsaKeyBin, RsaKeyFeature inputKeyType, RsaKeyFeature outputKeyType)
        {
            ValidateTransferRSAKeyTypes(inputKeyType, outputKeyType);

            string? inputRsaKey;
            switch (inputKeyType.Format)
            {
                case RsaKeyFormat.Xml:
                case RsaKeyFormat.Pem:
                    inputRsaKey = Encoding.UTF8.GetString(rsaKeyBin);
                    break;
                case RsaKeyFormat.Der:
                    inputRsaKey = RsaPemFormatHelper.PemRsaKeyFormat(Convert.ToBase64String(rsaKeyBin), inputKeyType.Padding, inputKeyType.IsPrivate);
                    inputKeyType.Format = RsaKeyFormat.Pem;
                    break;
                default:
                    throw new ArgumentException("Invalid RSA Key Type!", nameof(inputKeyType));
            }

            var outputFormat = outputKeyType.Format;
            if (outputKeyType.Format == RsaKeyFormat.Der)
                outputKeyType.Format = RsaKeyFormat.Pem;

            var outputRsaKey = Format(inputRsaKey, inputKeyType, outputKeyType);
            if (outputFormat == RsaKeyFormat.Der)
            {
                return Convert.FromBase64String(RsaPemFormatHelper.PemRsaKeyFormatRemove(outputRsaKey, outputKeyType.Padding, outputKeyType.IsPrivate));
            }
            else
            {
                return Encoding.UTF8.GetBytes(outputRsaKey);
            }
        }
    }

    public static class RsaKeyFeatureExtension_HIFBHDWFWES
    {
        public static void Validate(this RsaKeyFeature keyType, string? paramName = null)
        {
            if (!Enum.IsDefined(typeof(RsaKeyPadding), keyType.Padding) || keyType.Padding == RsaKeyPadding.Invalid)
                throw new ArgumentException("RSA key should have one valid padding.", paramName);

            switch (keyType.Format)
            {
                case RsaKeyFormat.Xml:
                    if (keyType.Padding != RsaKeyPadding.Xml)
                        throw new ArgumentException("The XML RSA Key Padding should be set as Xml.", paramName);
                    break;
                case RsaKeyFormat.Der:
                case RsaKeyFormat.Pem:
                    if (keyType.Padding == RsaKeyPadding.Xml)
                        throw new ArgumentException("The Xml Padding should only be used when Format is Xml.", paramName);
                    break;
                default:
                    throw new ArgumentException("Undefined RSA Key Format.", paramName);
            }
        }
    }
}

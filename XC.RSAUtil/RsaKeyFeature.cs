namespace XC.RSAUtil
{
    public enum RsaKeyPadding
    {
        Invalid,
        Xml,
        Pkcs1,
        Pkcs8,
    }

    public enum RsaKeyFormat
    {
        Invalid,
        Xml,
        Pem,
        Der,
    }

    public class RsaKeyFeature
    {
        public bool IsPrivate;
        public RsaKeyPadding Padding;
        public RsaKeyFormat Format;
    }
}

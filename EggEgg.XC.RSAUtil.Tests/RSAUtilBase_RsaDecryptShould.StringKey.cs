using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_RsaDecryptShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Encrypted_RSA4_01_Base64, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Encrypted_RSA4_02_Base64, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Encrypted_RSA4_01_Base64, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Encrypted_RSA4_02_Base64, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Encrypted_RSA4_01_Base64, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Encrypted_RSA4_02_Base64, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Encrypted_RSA5_01_Base64, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Encrypted_RSA5_02_Base64, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Encrypted_RSA5_01_Base64, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Encrypted_RSA5_02_Base64, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Encrypted_RSA5_01_Base64, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Encrypted_RSA5_02_Base64, TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaDecrypt_StringKey(string rsakey, string encrypted_base64, string expected_raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(rsakey);
        var res = key.RsaDecrypt(Convert.FromBase64String(encrypted_base64), RSAEncryptionPadding.Pkcs1);
        Assert.Equal(expected_raw_base64, Convert.ToBase64String(res));
    }
}

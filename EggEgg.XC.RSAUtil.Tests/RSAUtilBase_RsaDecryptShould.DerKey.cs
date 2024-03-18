using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_RsaDecryptShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Encrypted_RSA4_01_Base64, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Encrypted_RSA4_02_Base64, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Encrypted_RSA4_01_Base64, TestRSAData.Decrypted_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Encrypted_RSA4_02_Base64, TestRSAData.Decrypted_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Encrypted_RSA5_01_Base64, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Encrypted_RSA5_02_Base64, TestRSAData.Decrypted_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Encrypted_RSA5_01_Base64, TestRSAData.Decrypted_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Encrypted_RSA5_02_Base64, TestRSAData.Decrypted_RSA5_02_Base64)]
    public void RsaDecrypt_DerKey(string rsakeyPath, string encrypted_base64, string expected_raw_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var res = key.RsaDecrypt(Convert.FromBase64String(encrypted_base64), RSAEncryptionPadding.Pkcs1);
        Assert.Equal(expected_raw_base64, Convert.ToBase64String(res));
    }
}

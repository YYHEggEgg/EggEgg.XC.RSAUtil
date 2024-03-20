namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaPemFormatHelper_PemRsaKeyFormatRemoveShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    public void PemRsaKeyFormatRemove_Pkcs1Private(string pemKey, string expectedPath)
    {
        Assert.Equal(Convert.ToBase64String(File.ReadAllBytes(expectedPath)), RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKey, RsaKeyPadding.Pkcs1, true));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, "TestDerKeys/Pkcs1PublicKey_5.der")]
    public void PemRsaKeyFormatRemove_Pkcs1Public(string pemKey, string expectedPath)
    {
        Assert.Equal(Convert.ToBase64String(File.ReadAllBytes(expectedPath)), RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKey, RsaKeyPadding.Pkcs1, false));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    public void PemRsaKeyFormatRemove_Pkcs8Private(string pemKey, string expectedPath)
    {
        Assert.Equal(Convert.ToBase64String(File.ReadAllBytes(expectedPath)), RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKey, RsaKeyPadding.Pkcs8, true));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void PemRsaKeyFormatRemove_Pkcs8Public(string pemKey, string expectedPath)
    {
        Assert.Equal(Convert.ToBase64String(File.ReadAllBytes(expectedPath)), RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKey, RsaKeyPadding.Pkcs8, false));
    }
}

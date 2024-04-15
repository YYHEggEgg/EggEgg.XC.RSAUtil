namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyGenerator_GetKeyShould
{
    [Theory]
    [InlineData(RsaKeyFormat.Xml, RsaKeyPadding.Xml, 512)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, 512)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, 512)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs1, 512)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs8, 512)]
    [InlineData(RsaKeyFormat.Xml, RsaKeyPadding.Xml, 1024)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, 1024)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, 1024)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs1, 1024)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs8, 1024)]
    [InlineData(RsaKeyFormat.Xml, RsaKeyPadding.Xml, 2048)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs1, 2048)]
    [InlineData(RsaKeyFormat.Pem, RsaKeyPadding.Pkcs8, 2048)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs1, 2048)]
    [InlineData(RsaKeyFormat.Der, RsaKeyPadding.Pkcs8, 2048)]
    public void GetKey_AssertByLoading(RsaKeyFormat format, RsaKeyPadding padding, int keySize)
    {
        var keyResult = RsaKeyGenerator.GetKey(format, padding, keySize);

        var pubKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.PublicKey);
        Assert.Equal(format, pubKeyType.Format);
        Assert.Equal(padding, pubKeyType.Padding);
        Assert.False(pubKeyType.IsPrivate);

        var priKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.PrivateKey);
        Assert.Equal(format, priKeyType.Format);
        Assert.Equal(padding, priKeyType.Padding);
        Assert.True(priKeyType.IsPrivate);

        var rsa = keyResult.GetRSAInstance();
        Assert.Equal(keySize, rsa.PublicRsa?.KeySize);
        Assert.Equal(keySize, rsa.PrivateRsa?.KeySize);
    }
}

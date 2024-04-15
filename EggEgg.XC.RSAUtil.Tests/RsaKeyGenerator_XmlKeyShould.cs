namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyGenerator_XmlKeyShould
{
    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    public void XmlKey_AssertByLoading(int keySize)
    {
        var keyResult = RsaKeyGenerator.XmlKey(keySize);

        var pubKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.publicKey);
        Assert.Equal(RsaKeyFormat.Xml, pubKeyType.Format);
        Assert.Equal(RsaKeyPadding.Xml, pubKeyType.Padding);
        Assert.False(pubKeyType.IsPrivate);

        var priKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.privateKey);
        Assert.Equal(RsaKeyFormat.Xml, priKeyType.Format);
        Assert.Equal(RsaKeyPadding.Xml, priKeyType.Padding);
        Assert.True(priKeyType.IsPrivate);

        var rsa = RSAUtilBase.LoadRSAKey(keyResult.privateKey);
        Assert.Equal(keySize, rsa.PublicRsa?.KeySize);
        Assert.Equal(keySize, rsa.PrivateRsa?.KeySize);
    }
}

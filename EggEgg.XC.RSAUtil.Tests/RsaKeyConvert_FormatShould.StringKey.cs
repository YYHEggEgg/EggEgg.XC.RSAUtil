namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyConvert_FormatShould
{
    private RsaKeyFeature Pkcs1PrivatePemKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Pem,
    }; 
    private RsaKeyFeature Pkcs8PrivatePemKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature XmlPrivateKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Xml,
        Format = RsaKeyFormat.Xml,
    };
    private RsaKeyFeature Pkcs1PublicPemKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature Pkcs8PublicPemKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature XmlPublicKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Xml,
        Format = RsaKeyFormat.Xml,
    };

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_StringKey_Private_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PrivatePemKeyType, Pkcs8PrivatePemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_StringKey_Private_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PrivatePemKeyType, Pkcs1PrivatePemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_StringKey_Private_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PrivatePemKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_StringKey_Private_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPrivateKeyType, Pkcs1PrivatePemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_StringKey_Private_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PrivatePemKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_StringKey_Private_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPrivateKeyType, Pkcs8PrivatePemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_StringKey_Public_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PublicPemKeyType, Pkcs8PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_StringKey_Public_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PublicPemKeyType, Pkcs1PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_StringKey_Public_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PublicPemKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_StringKey_Public_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPublicKeyType, Pkcs1PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_StringKey_Public_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PublicPemKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_StringKey_Public_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPublicKeyType, Pkcs8PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_StringKey_Pkcs1_PrivateToPublic(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PrivatePemKeyType, Pkcs1PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_StringKey_Pkcs8_PrivateToPublic(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PrivatePemKeyType, Pkcs8PublicPemKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_StringKey_Xml_PrivateToPublic(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPrivateKeyType, XmlPublicKeyType));
    }
}

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyConvert_FormatShould
{
    private RsaKeyFeature Pkcs1PrivateDerKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Der,
    }; 
    private RsaKeyFeature Pkcs8PrivateDerKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Der,
    };
    private RsaKeyFeature Pkcs1PublicDerKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Der,
    };
    private RsaKeyFeature Pkcs8PublicDerKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Der,
    };

    private byte[] GetKeyBinFromDerFile(string filePath) =>
        File.ReadAllBytes(filePath);
    private byte[] GetKeyBinFromXml(string xmlKey) =>
        Encoding.UTF8.GetBytes(xmlKey);
    private void AssertSequenceEqual(byte[] expected, byte[] input) =>
        Assert.Equal(expected, input);
    private void AssertSequenceEqual(string expected, byte[] input) =>
        Assert.Equal(GetKeyBinFromXml(expected), input);


    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", "TestDerKeys/Pkcs8PrivateKey_5.der")]
    public void Format_DerKey_Private_Pkcs1ToPkcs8(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs1PrivateDerKeyType, Pkcs8PrivateDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", "TestDerKeys/Pkcs1PrivateKey_5.der")]
    public void Format_DerKey_Private_Pkcs8ToPkcs1(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs8PrivateDerKeyType, Pkcs1PrivateDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", TestRSAKeys.XmlPrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", TestRSAKeys.XmlPrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAKeys.XmlPrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAKeys.XmlPrivateKey_5)]
    public void Format_DerKey_Private_Pkcs1ToXml(string input, string expected)
    {
        AssertSequenceEqual(expected.ReplaceLineEndings(), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs1PrivateDerKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, "TestDerKeys/Pkcs1PrivateKey_2.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, "TestDerKeys/Pkcs1PrivateKey_3.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, "TestDerKeys/Pkcs1PrivateKey_4.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, "TestDerKeys/Pkcs1PrivateKey_5.der")]
    public void Format_DerKey_Private_XmlToPkcs1(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromXml(input), XmlPrivateKeyType, Pkcs1PrivateDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", TestRSAKeys.XmlPrivateKey_2)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", TestRSAKeys.XmlPrivateKey_3)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAKeys.XmlPrivateKey_4)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAKeys.XmlPrivateKey_5)]
    public void Format_DerKey_Private_Pkcs8ToXml(string input, string expected)
    {
        AssertSequenceEqual(expected.ReplaceLineEndings(), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs8PrivateDerKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, "TestDerKeys/Pkcs8PrivateKey_2.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, "TestDerKeys/Pkcs8PrivateKey_3.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, "TestDerKeys/Pkcs8PrivateKey_4.der")]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, "TestDerKeys/Pkcs8PrivateKey_5.der")]
    public void Format_DerKey_Private_XmlToPkcs8(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromXml(input), XmlPrivateKeyType, Pkcs8PrivateDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void Format_DerKey_Public_Pkcs1ToPkcs8(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs1PublicDerKeyType, Pkcs8PublicDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", "TestDerKeys/Pkcs1PublicKey_5.der")]
    public void Format_DerKey_Public_Pkcs8ToPkcs1(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs8PublicDerKeyType, Pkcs1PublicDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PublicKey_2.der", TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_3.der", TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_4.der", TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs1PublicKey_5.der", TestRSAKeys.XmlPublicKey_5)]
    public void Format_DerKey_Public_Pkcs1ToXml(string input, string expected)
    {
        AssertSequenceEqual(expected, RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs1PublicDerKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_3, "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_4, "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_5, "TestDerKeys/Pkcs1PublicKey_5.der")]
    public void Format_DerKey_Public_XmlToPkcs1(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromXml(input), XmlPublicKeyType, Pkcs1PublicDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs8PublicKey_2.der", TestRSAKeys.XmlPublicKey_2)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_3.der", TestRSAKeys.XmlPublicKey_3)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_4.der", TestRSAKeys.XmlPublicKey_4)]
    [InlineData("TestDerKeys/Pkcs8PublicKey_5.der", TestRSAKeys.XmlPublicKey_5)]
    public void Format_DerKey_Public_Pkcs8ToXml(string input, string expected)
    {
        AssertSequenceEqual(expected.ReplaceLineEndings(), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs8PublicDerKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_3, "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_4, "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData(TestRSAKeys.XmlPublicKey_5, "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void Format_DerKey_Public_XmlToPkcs8(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromXml(input), XmlPublicKeyType, Pkcs8PublicDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_2.der", "TestDerKeys/Pkcs1PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_3.der", "TestDerKeys/Pkcs1PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", "TestDerKeys/Pkcs1PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", "TestDerKeys/Pkcs1PublicKey_5.der")]
    public void Format_DerKey_Pkcs1_PrivateToPublic(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs1PrivateDerKeyType, Pkcs1PublicDerKeyType));
    }

    [Theory]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_2.der", "TestDerKeys/Pkcs8PublicKey_2.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_3.der", "TestDerKeys/Pkcs8PublicKey_3.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", "TestDerKeys/Pkcs8PublicKey_4.der")]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", "TestDerKeys/Pkcs8PublicKey_5.der")]
    public void Format_DerKey_Pkcs8_PrivateToPublic(string input, string expected)
    {
        AssertSequenceEqual(GetKeyBinFromDerFile(expected), RsaKeyConvert.Format(GetKeyBinFromDerFile(input), Pkcs8PrivateDerKeyType, Pkcs8PublicDerKeyType));
    }
}

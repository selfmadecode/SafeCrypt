using SafeCrypt.Helpers;
using SafeCrypt.Models;
using SafeCrypt.AES;

namespace SafeCrypt.UnitTests.AesTests;

public class EncryptionDecryption
{
    public const string Data = "Hello, World!";

    [Fact]
    public async Task EncryptToHexStringAsync_And_DecryptFromHexStringAsync_ValidParameters_ReturnsOriginalData()
    {
        // Arrange
        var aesIv = KeyGenerators.GenerateHexadecimalIVKey();
        var secret = KeyGenerators.GenerateAesSecretKey(256);

        var encryptionParameters = new EncryptionParameters
        {
            Data = Data,
            IV = aesIv,
            SecretKey = secret
        };

        // Act
        var encryptionResult = await Aes.EncryptToHexStringAsync(encryptionParameters);
        Assert.False(encryptionResult.HasError);
        
        var decryptionResult = await Aes.DecryptFromHexStringAsync(new DecryptionParameters
        {
            Data = encryptionResult.EncryptedData,
            IV = aesIv,
            SecretKey = secret
        });

        // Assert
        Assert.NotNull(encryptionResult.EncryptedData);
        Assert.Equal(Data, decryptionResult.DecryptedData);

        Assert.False(encryptionResult.HasError);
        Assert.False(decryptionResult.HasError);

        Assert.Empty(encryptionResult.Errors);
        Assert.Empty(decryptionResult.Errors);
    }

    [Theory]
    [InlineData(Data)]
    public async Task EncryptToBase64StringAndDecryptAsync_DecryptedDataMatchesOriginalData(string originalData)
    {
        // Arrange
        var aesIv = KeyGenerators.GenerateBase64IVKey();
        var secret = KeyGenerators.GenerateAesSecretKey(256);

        var encryptionParameters = new EncryptionParameters
        {
            Data = originalData,
            IV = aesIv,
            SecretKey = secret
        };

        // Act
        var encryptionResult = await Aes.EncryptToBase64StringAsync(encryptionParameters);
        Assert.False(encryptionResult.HasError);

        var decryptionParameters = new DecryptionParameters
        {
            Data = encryptionResult.EncryptedData,
            IV = aesIv,
            SecretKey = secret
        };

        var decryptionResult = await Aes.DecryptFromBase64StringAsync(decryptionParameters);
        Assert.False(decryptionResult.HasError);

        // Assert
        Assert.Equal(originalData, decryptionResult.DecryptedData);
    }
}

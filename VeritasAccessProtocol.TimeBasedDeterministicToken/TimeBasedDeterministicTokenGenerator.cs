using System.Security.Cryptography;
using System.Text;

namespace VeritasAccessProtocol.TimeBasedDeterministicToken;

/// <summary>
/// The Time-Based Deterministic Token generator.
/// </summary>
public class TimeBasedDeterministicTokenGenerator
{
    /// <summary>
    /// The shared secret for TDT generation.
    /// </summary>
    public string Secret { get; set; }

    private static Lazy<byte[]> customizationBytes = new Lazy<byte[]>(() =>
    {
        // Convert customization string "5beeb687e266" (hex) to big-endian byte array
        string customizationHex = "5beeb687e266";
        byte[] bytes = new byte[customizationHex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(customizationHex.Substring(i * 2, 2), 16);
        }
        return bytes;
    });

    /// <summary>
    /// Initialize the generator with a secret.
    /// </summary>
    /// <param name="secret">The shared secret string.</param>
    public TimeBasedDeterministicTokenGenerator(string secret)
    {
        // NFC Normalize
        secret = secret.Normalize(NormalizationForm.FormC);

        this.Secret = secret;
    }

    /// <summary>
    /// Generate a TDT value using the specified secret, timestamp, and result length.
    /// </summary>
    /// <param name="timestamp">Milliseconds UTC timestamp (Int64).</param>
    /// <param name="resultLength">Output length in bytes (default 256).</param>
    /// <returns>Byte array of TDT value.</returns>
    public byte[] Generate(long timestamp, int resultLength = 256)
    {
        // Encode the secret as UTF-8 bytes
        byte[] secretBytes = Encoding.UTF8.GetBytes(Secret);

        // Convert timestamp to 8-byte big-endian array
        byte[] timestampBytes = BitConverter.GetBytes(timestamp >= 0 ? timestamp : -timestamp);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(timestampBytes);
        }

        // Call KMAC128 to generate the TDT value
        byte[] result = Kmac128.HashData(secretBytes, timestampBytes, resultLength, customizationBytes.Value);

        return result;
    }

    /// <summary>
    /// Generate a TDT value using the current UTC timestamp and specified result length.
    /// </summary>
    /// <param name="resultLength">Output length in bytes (default 256).</param>
    /// <returns>Byte array of TDT value.</returns>
    public byte[] Generate(int resultLength = 256)
    {
        // Get current UTC timestamp in milliseconds
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        return Generate(timestamp, resultLength);
    }
}

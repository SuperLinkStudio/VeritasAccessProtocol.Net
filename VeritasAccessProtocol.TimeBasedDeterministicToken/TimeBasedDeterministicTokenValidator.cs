using System;
using System.Security.Cryptography;
using System.Text;

namespace VeritasAccessProtocol.TimeBasedDeterministicToken;

/// <summary>
/// The Time-Based Deterministic Token validator.
/// </summary>
public class TimeBasedDeterministicTokenValidator
{
    /// <summary>
    /// The Time-Based Deterministic Token generator instance.
    /// </summary>
    /// <remarks>
    /// This instance is used to generate tokens for validation.
    /// </remarks>
    private TimeBasedDeterministicTokenGenerator generator;

    /// <summary>
    /// Initialize the validator with a secret.
    /// </summary>
    /// <param name="secret">The shared secret string.</param>
    public TimeBasedDeterministicTokenValidator(string secret)
    {
        generator = new TimeBasedDeterministicTokenGenerator(secret);
    }

    /// <summary>
    /// Validate a TDT token against a timestamp.
    /// </summary>
    /// <param name="timestamp">Milliseconds UTC timestamp (Int64).</param>
    /// <param name="token">Byte array of TDT value.</param>
    /// <param name="resultLength">Output length in bytes (default 256).</param>
    /// <returns>True if the token is valid; otherwise, false.</returns>
    public bool Validate(long timestamp, byte[] token, int resultLength = 256)
    {
        // Generate the expected token for the given timestamp
        byte[] expectedToken = generator.Generate(timestamp, resultLength);

        // Compare the generated token with the provided token
        return CryptographicOperations.FixedTimeEquals(expectedToken, token);
    }

    /// <summary>
    /// Validate a TDT token against a timestamp.
    /// </summary>
    /// <param name="timestamp">Milliseconds UTC timestamp (Int64).</param>
    /// <param name="token">Byte array of TDT value.</param>
    /// <param name="resultLength">Output length in bytes (default 256).</param>
    /// <returns>True if the token is valid; otherwise, false.</returns>
    public bool Validate(long timestamp, byte[] token)
    {
        int resultLength = token.Length;

        // Compare the generated token with the provided token
        return Validate(timestamp, token, resultLength);
    }
}
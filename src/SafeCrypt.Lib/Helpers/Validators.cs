﻿using SafeCrypt.Models;
using System;

namespace SafeCrypt.Helpers
{
    internal static class Validators
    {      
        /// <summary>
        /// Validates whether the provided string is a valid Base64-encoded key.
        /// </summary>
        /// <param name="keyAsString">The string to validate.</param>
        /// <returns>True if the string is a valid Base64-encoded key; otherwise, false.</returns>
        internal static bool IsBase64String(string keyAsString)
        {
            if (string.IsNullOrEmpty(keyAsString))
            {
                return false;
            }

            try
            {
                byte[] data = Convert.FromBase64String(keyAsString);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        /// <summary>
        /// Validates whether the block size is valid for the AES algorithm.
        /// </summary>
        /// <param name="dataLength">The length of the data to be encrypted.</param>
        /// <returns>True if the block size is valid; otherwise, false.</returns>
        internal static bool IsValidBlockSize(int dataLength)
        {
            // AES block size is 128 bits (16 bytes)
            return dataLength % 16 == 0;
        }

        /// <summary>
        /// Validates whether the byte array is valid for a specific algorithm.
        /// </summary>
        /// <param name="byteArray">The byte array to validate.</param>
        /// <returns>True if the byte array is valid; otherwise, false.</returns>
        private static bool IsValidByteArray(byte[] byteArray)
        {
            // Add your specific validation criteria here
            // For example, you might check for non-null, non-empty, or other constraints

            return byteArray != null && byteArray.Length > 0;
        }
    }

    internal static class Validator<TParameters> where TParameters : BaseAesEncryptionParameters
    {
        /// <summary>
        /// Validates that the specified ByteEncryptionParameters instance is not null
        /// and that its required properties (Data, SecretKey, IV) are not null.
        /// </summary>
        /// <param name="parameters">The ByteEncryptionParameters instance to validate.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the specified parameters instance is null or if any of its required properties are null.
        /// </exception>
        internal static void ValidateNotNull(TParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters), $"{typeof(TParameters).Name} instance cannot be null.");
            }

            if (parameters.Data == null)
            {
                throw new ArgumentNullException(nameof(parameters.Data), "Data property cannot be null.");
            }

            if (parameters.SecretKey == null)
            {
                throw new ArgumentNullException(nameof(parameters.SecretKey), "SecretKey property cannot be null.");
            }

            if (parameters.IV == null)
            {
                throw new ArgumentNullException(nameof(parameters.IV), "IV property cannot be null.");
            }
        }
    }
}

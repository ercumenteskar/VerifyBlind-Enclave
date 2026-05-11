using VerifyBlind.Core.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Standalone IEnclaveKeyService implementation.
/// Manages enclave RSA key pair and attestation — no KMS dependency.
/// Replaces the enclave-local portion of MockHsm.
/// </summary>
public class EnclaveKeyService : IEnclaveKeyService
{
    private readonly string _enclavePrivKey;
    private readonly string _enclavePubKey;
    private readonly string _enclaveIdSignature;
    private readonly INsmProvider _nsm;

    // Manufacturer/Root Identity (same offline key as MockHsm)
    private const string MANUFACTURER_ROOT_PRIV_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCc8yVBXtww4UJijvjs3bTvEg1TYcHV2mIN0P3IZTtu3kXYxHgNzLslZFrmWzveXIJjA/mHUCIRBuql1qv684J/rDSmryRJQYDbsjCQBvrTnYoLFPdHYfzyZYuntVUIRw5FEuS8MnlLwHwRV9y6G5TyynCnSH2YaDJMubFVGDWj2BvxPOCu6xveYVEjK3ERSTzAfsM5xXI9bcMzetHjemuA5Pjdzl05XI0F52ciPFE4b+Zk404ucOSi3IyYSLkJZ7T5vwfMVvox9OUzOEje6BzWHm0cpPI0PiZrzFKLzyeyMuxzHHGDJKN962cQkNjWPG1BIlQaOw0LsikDYLwPYYadAgMBAAECggEAKQEVQKjp2hNf5qP3wNqDhNowhRJLM/XkHDv3sb1Q87w6f1GFFAXi9vfrD7fSQlvk7L2DGakD3XLzJvSY5e1ssLJq5wlm74Sfh8ZcDaTlLxg/knmdyRZ+oU2KWPx1BL6bqcwv2kNNkU7umxFbZ3wBRBVDrVCxD3pZedYh0FuM2AsbKmwyEGjoseJZEBjF1XAifYIBgn5dM40Bb5L2grZBKzMIeKv+jo4FSd6EoA3eP5bBvdVP9Zm+MvbX+SSpZFtEyih4c1+MvHcotN+2heEIKrQ1mtrujKvFybKKZOBWvMrZEhH5vD4a/Rq0vZ0VXA3aPfleMNo0DHkPRa79hx+p+QKBgQDC81GOLjnMFz5IQXIL6vMHquLp50zWyLJE6QuiAMb27j01mo5B5kej22YPh8Agn6H0YydLASdttx9dTCYuekjM8aMbgxvpOpcUJNkrR4ZbwfI6Dc3fBxZi8NTd+zr9b9DhQZOhYEq0yCoj0uDUpvioSjrHHaxigVNMqv9Z/JHgQwKBgQDOGWjgvhGsMkOOF9nmmM5b3774Q6vGoyOKitbrYe1RzcVIL6guTgT5jfc2brMeAVxDks7qC3DwhqavA3YFxjjf/w88KNDZWKwszFbfEfYK8XrACPDzL6HpIt4JT62eS88DMhZB4lKpnahbEaSb1fxqkfUndmBc30dUsaMXhgJ/nwKBgBpnMeh7wkAt9bV7h6Ktk3S6ZDkhpnqAfARxO64ZRNk0sv2LjTDHq3Q5xrzbud2xQRIES9IQufJWFt1f7tvkm++F2n1jaGhSExwbUX5XFY9f2RqbvAI0x4dm7q2R1Q92EWgwpXn5vKR3Z52qdeDXLF4+j29gSXSd51Y+4o6hcnBZAoGAfxlsdCzC+U6GGrraxjq2CDKTsscIyBcTc/zrTX22vRwI7dt1/BhhOQUzz321OGveWk3PDMbBf5OKd6PKxQTZTkodOxxwr5jflUDu0eJhuZ3x9TuOXGqjjwLRqyxYBab6ox3gXAEWuUNg78iRmwj8ATzB0vRNuPh5JOHnkjoykEECgYEAnI6faaH2FI58jswNee8rfXyr+huj9kRNBN5pB2tZVRc0+Gq42CPdyzA/dMQp7IJUitbNzJP+TW+6tv4/82TBUjLKQkCiJbTGATmt2PNhljiuLoHWWmA2nGorwEXHqfH9WOVgsiwmSPwDrpsuLf5m74xIKL5L8qh+AX0tSSi5e5Y=";

    private readonly bool _useStaticKeys;

    public EnclaveKeyService(INsmProvider nsm, bool useStaticKeys = true)
    {
        _nsm = nsm;
        _useStaticKeys = useStaticKeys;

        if (_useStaticKeys)
        {
            _enclavePrivKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDlEbr76rKLFcLNf89Ad6/mbCRSxt3tbD1erazCIgqtyDVye3ADK1Q8jMKwt0+G5sfbR7uhuFQKf+C9/XGBk+gE7gbfbZnZutRXI1cTE/tzI5YVjlH+IBP9AOx/rhAOtUIV9oKnjITvuqhO6FACNOk12txdXhV8s/0/jNbd+P5UNzEohuvCYUyoCfmvnadyIsid/1YIEgiwOLFr2YIT4bVAYM6+jVDyBtfg+DXSbthYGqpl6eRayGzkZQBwUh+/HkMJTc8rbG/5Vf8Ba2BlN2VC3nn6CY+rcyTXl6FiqTIneYb6iyOr0DQJB+5CNXi3+kheYc82cQehp56vrm4D/vThAgMBAAECggEBANybcsTihwjD8FQQ3vxrSBBV3bWKqHjbYU8pW9OrDTXINxEGKB4lQH7/4RBnukNlRty7/MwGxYlHFp5i00nDtBPrWNscpqq174HsGxPYjrWYdBZWdkiThCyJEzrz26sOjZKxUasi/XQTA7zapxM4+dBP8yJIVdE/Voo5jUVBY06d9bHKoWqgHtyjTlLk5GSE2lmVnoqopn68wSKWO8MKVV1ZZZvWGRSFgOTfRh5ohfZhEljLpR61daFd7URx2fDd//aQN44wN7ABTxA6H6/2nbeaaiUhdKc/Y9LAjLsgX10obIaTc4fUYh342lngSVAmZaVj6Mj9wqm4ie4jELY2rzECgYEA/4VJ8mavDN2EWV+to5sJMRiDCm7LEgmfNmfs1Gbjv6E0drtfjfuLX0pd5HwExMHqLi1P9jdBmArzEHJKuaFE5C/khMwFcR2HU/KJOFufJ0tFDKX8QPMvznRnsvkbd9zOTXYZTFOWwGxNtENJ4lRjp3pq8uhSdn0qpnMT/q88HB8CgYEA5X+9EQYoGFCWz863P/HdWz0w6usQ7rxkO8rujQcXl4X3S5RrBSFaJBmL+s7BBRpe+wVj1NHT8XUNWoa8mJx2UaxKlf/ogUAyrWNfqpWVRCfhtuw0As3sChOr4q8BJuwI2Nu21W7fpLJf47R5MdSO1WijfgodKCiUcoXqeRfCzv8CgYEAtM12vpvj/4F7FdZ6wkqAnYnPp4EwFepTCydMUBshykXiHqWE/q1gOCQh/fu3UBY6g0Qy0XDV7CTLSvbkYyd23NP6qfDHZPvU9xSl/gfuvNoo2MNWlAq/6CE8A0r7IbxPCkanrfdzs2KvNP9r90dpYGdh59F2EDuPA0poeo06RlcCgYB71qYLHatdE3+NuxofI0AzD53p5dZJPNdJfIOlDgKo/N0op3noVsrxV+e0+wQk4MoH4iywllkrneIKy1HRd/xQrgvBTUoFFMND1K+2uOjG0k52Cpc2PC/2cA78Tzrr6coMWuMZ4K5FjQs5MBWF0hERD1nJlWOOW/depOyVU0EHuQKBgQCFrASvwt+86CkWkcScy12quji8jYYKLXBVTBW86gBhUYGOIjfklidgyKul+ohC64nRjEGcxb7Ln9RCB5ml9tpXpqmw6mQurJGm30pl6LeS8jk1u/gTuIOXYHReDwX5gb2a6QuPGguDjnyWpcubz6PdD4CM15CEtnqZ1TFSqYd1VQ==";
            _enclavePubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5RG6++qyixXCzX/PQHev5mwkUsbd7Ww9Xq2swiIKrcg1cntwAytUPIzCsLdPhubH20e7obhUCn/gvf1xgZPoBO4G322Z2brUVyNXExP7cyOWFY5R/iAT/QDsf64QDrVCFfaCp4yE77qoTuhQAjTpNdrcXV4VfLP9P4zW3fj+VDcxKIbrwmFMqAn5r52nciLInf9WCBIIsDixa9mCE+G1QGDOvo1Q8gbX4Pg10m7YWBqqZenkWshs5GUAcFIfvx5DCU3PK2xv+VX/AWtgZTdlQt55+gmPq3Mk15ehYqkyJ3mG+osjq9A0CQfuQjV4t/pIXmHPNnEHoaeer65uA/704QIDAQAB";
            _enclaveIdSignature = CryptoUtils.SignData(_enclavePubKey, MANUFACTURER_ROOT_PRIV_KEY);

            Console.WriteLine("[EnclaveKeyService] DevMode ACTIVE (Static Keys with Root Trust)");
        }
        else
        {
            using var rsa = RSA.Create(2048);
            _enclavePrivKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            _enclavePubKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            _enclaveIdSignature = CryptoUtils.SignData(_enclavePubKey, MANUFACTURER_ROOT_PRIV_KEY);

            Console.WriteLine("[EnclaveKeyService] ProdMode ACTIVE. Keys certified by Root Key.");
        }
    }

    public string GetEnclavePublicKey() => _enclavePubKey;
    public string GetEnclaveIdentitySignature() => _enclaveIdSignature;
    public string SignDataWithEnclaveKey(string data) => CryptoUtils.SignData(data, _enclavePrivKey);
    public bool VerifyEnclaveSignature(string data, string signature) => CryptoUtils.VerifySignature(data, signature, _enclavePubKey);
    public string DecryptWithEnclaveKey(string cipherText) => CryptoUtils.RsaDecrypt(cipherText, _enclavePrivKey);

    private string? _cachedAttestationDoc;

    public string GetAttestationDocument()
    {
        if (_cachedAttestationDoc != null) return _cachedAttestationDoc;
        var pubKeyBytes = Encoding.UTF8.GetBytes(_enclavePubKey);
        var docBytes = _nsm.GetAttestationDocument(userData: pubKeyBytes);
        _cachedAttestationDoc = Convert.ToBase64String(docBytes);
        Console.WriteLine("[EnclaveKeyService] Attestation belgesi oluşturuldu ve önbelleğe alındı.");
        return _cachedAttestationDoc;
    }
}

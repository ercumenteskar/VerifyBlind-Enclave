namespace VerifyBlind.Enclave.Services;

public interface IEnclaveKeyService
{
    string GetEnclavePublicKey();
    string GetEnclaveIdentitySignature();
    string SignDataWithEnclaveKey(string data);
    bool VerifyEnclaveSignature(string data, string signature);
    string DecryptWithEnclaveKey(string cipherText);
    string GetAttestationDocument();
}

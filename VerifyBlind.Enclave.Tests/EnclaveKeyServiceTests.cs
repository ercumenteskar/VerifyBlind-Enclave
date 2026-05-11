using VerifyBlind.Core.Crypto;
using VerifyBlind.Enclave.Services;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class EnclaveKeyServiceTests
{
    private readonly Mock<INsmProvider> _nsm = new();
    private readonly EnclaveKeyService _service;

    public EnclaveKeyServiceTests()
    {
        // Setup NSM to return fake attestation bytes
        _nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        // useStaticKeys=true → uses hardcoded test keys
        _service = new EnclaveKeyService(_nsm.Object, useStaticKeys: true);
    }

    // ── Key Material ──────────────────────────────────────────────────────────

    [Fact]
    public void GetEnclavePublicKey_ReturnsNonEmpty()
    {
        var pubKey = _service.GetEnclavePublicKey();
        Assert.NotEmpty(pubKey);
    }

    [Fact]
    public void GetEnclaveIdentitySignature_ReturnsNonEmpty()
    {
        var sig = _service.GetEnclaveIdentitySignature();
        Assert.NotEmpty(sig);
    }

    [Fact]
    public void GetEnclavePublicKey_IsValidBase64()
    {
        var pubKey = _service.GetEnclavePublicKey();
        var bytes = Convert.FromBase64String(pubKey);
        Assert.True(bytes.Length > 0);
    }

    // ── Sign & Verify ─────────────────────────────────────────────────────────

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        const string data = "test-data-12345";
        var signature = _service.SignDataWithEnclaveKey(data);
        var isValid = _service.VerifyEnclaveSignature(data, signature);

        Assert.NotEmpty(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyEnclaveSignature_TamperedData_Fails()
    {
        const string data = "original-data";
        var signature = _service.SignDataWithEnclaveKey(data);

        var isValid = _service.VerifyEnclaveSignature("tampered-data", signature);
        Assert.False(isValid);
    }

    [Fact]
    public void Sign_DifferentData_ProducesDifferentSignatures()
    {
        var sig1 = _service.SignDataWithEnclaveKey("data-one");
        var sig2 = _service.SignDataWithEnclaveKey("data-two");

        Assert.NotEqual(sig1, sig2);
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    [Fact]
    public void DecryptWithEnclaveKey_AfterRsaEncrypt_RoundTrips()
    {
        var pubKey = _service.GetEnclavePublicKey();
        var cipherText = CryptoUtils.RsaEncrypt("hello-enclave", pubKey);

        var decrypted = _service.DecryptWithEnclaveKey(cipherText);
        Assert.Equal("hello-enclave", decrypted);
    }

    // ── Dynamic keys (useStaticKeys = false) ───────────────────────────────────

    [Fact]
    public void Constructor_DynamicKeys_GeneratesDifferentPublicKeys()
    {
        var nsm = new Mock<INsmProvider>();
        nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(Array.Empty<byte>());

        var svc1 = new EnclaveKeyService(nsm.Object, useStaticKeys: false);
        var svc2 = new EnclaveKeyService(nsm.Object, useStaticKeys: false);

        Assert.NotEqual(svc1.GetEnclavePublicKey(), svc2.GetEnclavePublicKey());
    }

    [Fact]
    public void Constructor_DynamicKeys_SignVerifyWorks()
    {
        var nsm = new Mock<INsmProvider>();
        var svc = new EnclaveKeyService(nsm.Object, useStaticKeys: false);

        var sig = svc.SignDataWithEnclaveKey("dynamic-data");
        Assert.True(svc.VerifyEnclaveSignature("dynamic-data", sig));
    }

    // ── Attestation ───────────────────────────────────────────────────────────

    [Fact]
    public void GetAttestationDocument_CallsNsmProvider()
    {
        var attestation = _service.GetAttestationDocument();

        _nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()), Times.Once);
        Assert.NotEmpty(attestation);
    }

    [Fact]
    public void GetAttestationDocument_IsCachedOnSecondCall()
    {
        var first = _service.GetAttestationDocument();
        var second = _service.GetAttestationDocument();

        // NSM should only be called once (cached after first call)
        _nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()), Times.Once);
        Assert.Equal(first, second);
    }
}

using VerifyBlind.Core.Crypto;
using VerifyBlind.Enclave.Services;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
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

    [Fact]
    public void GetAttestationDocument_PassesEnclavePublicKeyAsUserData()
    {
        // The attestation must be bound to the enclave's public key — the key bytes are
        // submitted to the NSM as user_data so a verifier can trust the key came from this enclave.
        var expectedUserData = Encoding.UTF8.GetBytes(_service.GetEnclavePublicKey());

        _service.GetAttestationDocument();

        _nsm.Verify(n => n.GetAttestationDocument(
            It.Is<byte[]>(b => b.SequenceEqual(expectedUserData)),
            It.IsAny<byte[]?>(),
            It.IsAny<byte[]?>()), Times.Once);
    }

    // ── Error Paths ───────────────────────────────────────────────────────────

    [Fact]
    public void VerifyEnclaveSignature_GarbageSignature_ReturnsFalseNeverThrows()
    {
        // VerifyEnclaveSignature delegates to CryptoUtils.VerifySignature, which must
        // never throw — malformed input is a "false", not a crash.
        Assert.False(_service.VerifyEnclaveSignature("data", "not-base64!!!"));
    }

    [Fact]
    public void VerifyEnclaveSignature_SignatureFromForeignKey_ReturnsFalse()
    {
        var (foreignPriv, _) = CryptoUtils.GenerateRsaKeyPair();
        var foreignSig = CryptoUtils.SignData("data", foreignPriv);

        Assert.False(_service.VerifyEnclaveSignature("data", foreignSig));
    }

    [Fact]
    public void DecryptWithEnclaveKey_GarbageCipherText_Throws()
        => Assert.ThrowsAny<Exception>(() => _service.DecryptWithEnclaveKey("not-base64!!!"));

    [Fact]
    public void DecryptWithEnclaveKey_CipherForDifferentKey_Throws()
    {
        var (_, foreignPub) = CryptoUtils.GenerateRsaKeyPair();
        var cipher = CryptoUtils.RsaEncrypt("secret", foreignPub);

        // Encrypted to someone else's key — this enclave must not be able to decrypt it.
        Assert.ThrowsAny<CryptographicException>(() => _service.DecryptWithEnclaveKey(cipher));
    }

    // ── Signature Properties ──────────────────────────────────────────────────

    [Fact]
    public void SignDataWithEnclaveKey_SameDataTwice_ProducesDifferentSignatures()
    {
        // RSA-PSS uses a random salt — identical input must not produce identical signatures.
        Assert.NotEqual(_service.SignDataWithEnclaveKey("x"), _service.SignDataWithEnclaveKey("x"));
    }

    [Fact]
    public void EmptyData_SignAndVerify_RoundTrips()
    {
        var sig = _service.SignDataWithEnclaveKey("");
        Assert.True(_service.VerifyEnclaveSignature("", sig));
    }

    [Fact]
    public void GetEnclaveIdentitySignature_IsStableAcrossCalls()
    {
        // The identity signature is computed once in the constructor — it must not change.
        Assert.Equal(_service.GetEnclaveIdentitySignature(), _service.GetEnclaveIdentitySignature());
    }

    // ── Static vs Dynamic Key Material ────────────────────────────────────────

    [Fact]
    public void StaticKeys_TwoInstances_ProduceIdenticalPublicKey()
    {
        var nsm = new Mock<INsmProvider>();
        var a = new EnclaveKeyService(nsm.Object, useStaticKeys: true);
        var b = new EnclaveKeyService(nsm.Object, useStaticKeys: true);

        // Static mode uses hardcoded dev keys — every instance is identical.
        Assert.Equal(a.GetEnclavePublicKey(), b.GetEnclavePublicKey());
    }

    [Fact]
    public void DynamicKeys_DecryptWithEnclaveKey_RoundTrips()
    {
        var nsm = new Mock<INsmProvider>();
        var svc = new EnclaveKeyService(nsm.Object, useStaticKeys: false);

        var cipher = CryptoUtils.RsaEncrypt("dynamic-secret", svc.GetEnclavePublicKey());
        Assert.Equal("dynamic-secret", svc.DecryptWithEnclaveKey(cipher));
    }

    [Fact]
    public void DynamicKeys_CrossInstanceSignature_DoesNotVerify()
    {
        var nsm = new Mock<INsmProvider>();
        var a = new EnclaveKeyService(nsm.Object, useStaticKeys: false);
        var b = new EnclaveKeyService(nsm.Object, useStaticKeys: false);

        var sigFromA = a.SignDataWithEnclaveKey("payload");
        // Dynamic keys are unique per instance — A's signature must not verify on B.
        Assert.False(b.VerifyEnclaveSignature("payload", sigFromA));
    }

    // ── Program.cs DI Behaviour ───────────────────────────────────────────────
    // Program.cs:35 registers IEnclaveKeyService → EnclaveKeyService with no factory.
    // The constructor's `bool useStaticKeys = true` default flows through Microsoft DI
    // (which substitutes ConstantCallSite from parameter.DefaultValue for unresolvable
    // primitives), so EVERY environment — including production — instantiates static
    // mode unless the registration is changed to an explicit factory. These tests pin
    // that current reality and will turn red the moment Program.cs is fixed.

    [Fact]
    public void DiContainer_MirroringProgramCs_InstantiatesInStaticMode()
    {
        // Arrange: replicate Program.cs:27,35 exactly.
        var services = new ServiceCollection();
        services.AddSingleton<INsmProvider>(_ =>
        {
            var nsm = new Mock<INsmProvider>();
            nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
                .Returns(new byte[] { 0x00 });
            return nsm.Object;
        });
        services.AddSingleton<IEnclaveKeyService, EnclaveKeyService>();

        using var sp = services.BuildServiceProvider();
        var diInstance = sp.GetRequiredService<IEnclaveKeyService>();

        // Assert: the public key returned by the DI-built instance equals the public key
        // of an explicit `useStaticKeys: true` construction — proving the DI container
        // fell back to the constructor's default and IS using the hardcoded static keys.
        var staticReference = new EnclaveKeyService(
            Mock.Of<INsmProvider>(), useStaticKeys: true).GetEnclavePublicKey();

        Assert.Equal(staticReference, diInstance.GetEnclavePublicKey());
    }

    [Fact]
    public void DiContainer_MirroringProgramCs_DoesNotProduceDynamicKeys()
    {
        // Two separate DI containers must return IDENTICAL public keys, which can only
        // happen in static mode (dynamic mode generates fresh RSA per instance).
        IEnclaveKeyService Build()
        {
            var s = new ServiceCollection();
            s.AddSingleton<INsmProvider>(_ => Mock.Of<INsmProvider>());
            s.AddSingleton<IEnclaveKeyService, EnclaveKeyService>();
            return s.BuildServiceProvider().GetRequiredService<IEnclaveKeyService>();
        }

        Assert.Equal(Build().GetEnclavePublicKey(), Build().GetEnclavePublicKey());
    }
}

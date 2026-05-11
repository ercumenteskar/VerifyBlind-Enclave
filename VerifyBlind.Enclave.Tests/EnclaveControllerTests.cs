using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Controllers;
using VerifyBlind.Enclave.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class EnclaveControllerTests
{
    private readonly Mock<IEnclaveKeyService> _enclaveKeys = new();
    private readonly Mock<IKmsService> _kms = new();
    private readonly Mock<IBiometricService> _biometrics = new();
    private readonly EnclaveService _service;
    private readonly EnclaveController _controller;

    public EnclaveControllerTests()
    {
        _enclaveKeys.Setup(k => k.GetEnclavePublicKey()).Returns("fake-pub-key");
        _enclaveKeys.Setup(k => k.GetEnclaveIdentitySignature()).Returns("fake-identity-sig");
        _enclaveKeys.Setup(k => k.SignDataWithEnclaveKey(It.IsAny<string>())).Returns("fake-sig");
        _enclaveKeys.Setup(k => k.GetAttestationDocument()).Returns("fake-attestation");

        _service = new EnclaveService(_enclaveKeys.Object, _kms.Object, _biometrics.Object);
        _controller = new EnclaveController(_service, _enclaveKeys.Object);
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    [Fact]
    public void Handshake_Success_ReturnsOk()
    {
        var result = Assert.IsType<OkObjectResult>(_controller.Handshake());
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void Handshake_ResponseHasNonceAndChallenges()
    {
        var result = Assert.IsType<OkObjectResult>(_controller.Handshake());
        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("nonce", json);
        Assert.Contains("challenges", json);
    }

    [Fact]
    public void Handshake_ServiceThrows_ReturnsBadRequest()
    {
        _enclaveKeys.Setup(k => k.SignDataWithEnclaveKey(It.IsAny<string>()))
            .Throws(new InvalidOperationException("Key not available"));

        var result = Assert.IsType<BadRequestObjectResult>(_controller.Handshake());
        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("error", json);
    }

    // ── LoginHandshake ────────────────────────────────────────────────────────

    [Fact]
    public void LoginHandshake_Success_ReturnsOk()
    {
        var result = Assert.IsType<OkObjectResult>(_controller.LoginHandshake());
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void LoginHandshake_ResponseHasAttestationDocument()
    {
        var result = Assert.IsType<OkObjectResult>(_controller.LoginHandshake());
        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("attestation_document", json);
        Assert.Contains("fake-attestation", json);
    }

    [Fact]
    public void LoginHandshake_ServiceThrows_ReturnsBadRequest()
    {
        _enclaveKeys.Setup(k => k.GetAttestationDocument())
            .Throws(new InvalidOperationException("NSM unavailable"));

        var result = Assert.IsType<BadRequestObjectResult>(_controller.LoginHandshake());
        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("error", json);
    }

    // ── Register ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Register_ServiceThrows_ReturnsBadRequest()
    {
        // When DecryptWithEnclaveKey throws, service propagates the error
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Throws(new RegistrationException(RegistrationStep.RsaDecrypt, "Decryption failed"));

        var request = new RegistrationRequest { EncryptedKey = "bad-key", AesBlob = "bad-blob" };
        var result = Assert.IsType<ObjectResult>(await _controller.Register(request));
        Assert.Equal(400, result.StatusCode);

        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("error", json);
    }

    [Fact]
    public async Task Register_ResponseContainsDiagEntries()
    {
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Throws(new RegistrationException(RegistrationStep.RsaDecrypt, "intentional error for diag test"));

        var request = new RegistrationRequest { EncryptedKey = "k", AesBlob = "b" };
        var result = Assert.IsType<ObjectResult>(await _controller.Register(request));
        Assert.Equal(400, result.StatusCode);

        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("enclave_diag", json);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_ServiceThrows_ReturnsBadRequest()
    {
        _kms.Setup(k => k.VerifyTicketSignatureAsync(It.IsAny<SignedTicket>()))
            .ThrowsAsync(new Exception("Invalid ticket"));

        var request = new LoginRequest
        {
            Nonce = Guid.NewGuid().ToString(),
            EncrSignedTicket = "bad-ticket"
        };
        var result = Assert.IsType<ObjectResult>(await _controller.Login(request));
        Assert.Equal(400, result.StatusCode);

        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("error", json);
    }
}

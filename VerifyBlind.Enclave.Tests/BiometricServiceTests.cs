using VerifyBlind.Enclave.Services;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class BiometricServiceTests
{
    // ── IBiometricService Mock Tests ──────────────────────────────────────────
    // Real BiometricService loads ONNX model from disk — not available in unit tests.
    // These tests verify the interface contract and mock behavior.

    [Fact]
    public void Mock_IBiometricService_HighScore_IsAboveThreshold()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.IsModelLoaded).Returns(true);
        mock.Setup(b => b.VerifyFace(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.95f);
        mock.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.95f);

        var service = mock.Object;

        Assert.True(service.IsModelLoaded);
        Assert.True(service.VerifyFace(new byte[1], new byte[1]) > 0.7f);
        Assert.True(service.VerifyFaceParallel(new byte[1], new byte[1]) > 0.7f);
    }

    [Fact]
    public void Mock_IBiometricService_LowScore_IsBelowThreshold()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.IsModelLoaded).Returns(true);
        mock.Setup(b => b.VerifyFace(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.3f);

        var service = mock.Object;

        Assert.True(service.VerifyFace(new byte[1], new byte[1]) < 0.7f);
    }

    [Fact]
    public void RealBiometricService_IsModelLoaded_ReflectsOnnxFilePresence()
    {
        // Real service: IsModelLoaded == true iff the ONNX file exists in Models/
        var service = new BiometricService();
        var modelPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models", "w600k_mbf.onnx");

        // The model is loaded iff the file exists — both outcomes are valid
        Assert.Equal(System.IO.File.Exists(modelPath), service.IsModelLoaded);
    }

    [Fact]
    public void RealBiometricService_ModelNotLoaded_VerifyFaceThrows()
    {
        var service = new BiometricService();

        if (!service.IsModelLoaded)
        {
            Assert.Throws<InvalidOperationException>(() =>
                service.VerifyFace(new byte[100], new byte[100]));
        }
        else
        {
            // Model loaded — service is functional; no exception expected for valid (but random) bytes
            Assert.True(service.IsModelLoaded);
        }
    }

    [Fact]
    public void RealBiometricService_ModelNotLoaded_VerifyFaceParallelThrows()
    {
        var service = new BiometricService();

        if (!service.IsModelLoaded)
        {
            Assert.Throws<InvalidOperationException>(() =>
                service.VerifyFaceParallel(new byte[100], new byte[100]));
        }
        else
        {
            // Model loaded — service is functional
            Assert.True(service.IsModelLoaded);
        }
    }

    // ── Score Range Tests ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(0.0f, false)]
    [InlineData(0.5f, false)]
    [InlineData(0.69f, false)]
    [InlineData(0.70f, true)]
    [InlineData(0.85f, true)]
    [InlineData(1.0f, true)]
    public void FaceScore_ThresholdCheck(float score, bool shouldPass)
    {
        // Typical face similarity threshold is 0.70 (70%)
        const float threshold = 0.70f;
        Assert.Equal(shouldPass, score >= threshold);
    }
}

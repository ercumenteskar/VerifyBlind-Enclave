using VerifyBlind.Core.Models;
using System.Text.Json;
using Xunit;

namespace VerifyBlind.Core.Tests;

/// <summary>
/// Tests for model classes at 0% coverage — simple property access and serialization.
/// </summary>
public class SharedModelsTests
{
    // ── PartnerRequest ────────────────────────────────────────────────────────

    [Fact]
    public void PartnerRequest_SetProperties_RoundTrips()
    {
        var pr = new PartnerRequest
        {
            Request = JsonSerializer.Deserialize<System.Text.Json.JsonElement>("{\"k\":1}"),
            Sign = "my-signature"
        };
        Assert.Equal("my-signature", pr.Sign);
        Assert.Equal(JsonValueKind.Object, pr.Request.ValueKind);
    }

    [Fact]
    public void PartnerRequest_JsonRoundTrip_Succeeds()
    {
        var pr = new PartnerRequest
        {
            Request = JsonSerializer.Deserialize<System.Text.Json.JsonElement>("{\"k\":1}"),
            Sign = "sig123"
        };
        var json = JsonSerializer.Serialize(pr);
        var deserialized = JsonSerializer.Deserialize<PartnerRequest>(json);
        Assert.Equal("sig123", deserialized!.Sign);
    }

    // ── LoginResponse ─────────────────────────────────────────────────────────

    [Fact]
    public void LoginResponse_SetProperties_Accessible()
    {
        var lr = new LoginResponse
        {
            Nonce = "nonce-xyz",
            SpecialData = new { foo = 1 },
            Validations = new Dictionary<string, object> { ["age"] = "18+", ["user_id"] = "user-abc" }
        };

        Assert.Equal("nonce-xyz", lr.Nonce);
        Assert.NotNull(lr.SpecialData);
        Assert.Equal(2, lr.Validations!.Count);
        Assert.Equal("user-abc", lr.Validations["user_id"]);
    }

    [Fact]
    public void LoginResponse_NullableFields_DefaultNull()
    {
        var lr = new LoginResponse { Nonce = "n" };
        Assert.Null(lr.SpecialData);
        Assert.Null(lr.Validations);
    }

    [Fact]
    public void LoginResponse_JsonRoundTrip_Succeeds()
    {
        var lr = new LoginResponse
        {
            Nonce = "n1",
            Validations = new Dictionary<string, object> { ["user_id"] = "u1" }
        };
        var json = JsonSerializer.Serialize(lr);
        var des = JsonSerializer.Deserialize<LoginResponse>(json);
        Assert.Equal("n1", des!.Nonce);
        Assert.Equal("u1", des.Validations!["user_id"].ToString());
    }

    // ── SignedLoginResponse ───────────────────────────────────────────────────

    [Fact]
    public void SignedLoginResponse_SetProperties_Accessible()
    {
        var slr = new SignedLoginResponse
        {
            Payload = "{\"nonce\":\"abc\"}",
            Signature = "base64-sig"
        };

        Assert.Equal("{\"nonce\":\"abc\"}", slr.Payload);
        Assert.Equal("base64-sig", slr.Signature);
    }

    [Fact]
    public void SignedLoginResponse_JsonRoundTrip_Succeeds()
    {
        var slr = new SignedLoginResponse { Payload = "p", Signature = "s" };
        var json = JsonSerializer.Serialize(slr);
        var des = JsonSerializer.Deserialize<SignedLoginResponse>(json);
        Assert.Equal("p", des!.Payload);
        Assert.Equal("s", des.Signature);
    }

    // ── PartnerRequestData — cover uncovered optional properties ──────────────

    [Fact]
    public void PartnerRequestData_OptionalProperties_Accessible()
    {
        var prd = new PartnerRequestData
        {
            PartnerId = "pid",
            Nonce = "nonce",
            PublicKey = "pubkey",
            CallbackUrl = "https://example.com/cb",
            SpecialData = new { x = 1 },
            Validations = new Dictionary<string, object> { ["age"] = "18+" }
        };

        Assert.Equal("https://example.com/cb", prd.CallbackUrl);
        Assert.NotNull(prd.SpecialData);
        Assert.Single(prd.Validations!);
    }

    // ── LoginRequest — cover optional fields ──────────────────────────────────

    [Fact]
    public void LoginRequest_OptionalFields_Accessible()
    {
        var lr = new LoginRequest
        {
            EncrSignedTicket = "enc",
            Nonce = "nonce",
            IntegrityToken = "it",
            PartnerPublicKey = "ppk",
            QrPayloadJson = "{\"k\":1}",
            CallbackUrl = "https://cb.test"
        };

        Assert.Equal("ppk", lr.PartnerPublicKey);
        Assert.Equal("{\"k\":1}", lr.QrPayloadJson);
        Assert.Equal("https://cb.test", lr.CallbackUrl);
    }
}

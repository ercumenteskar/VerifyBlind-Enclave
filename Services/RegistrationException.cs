namespace VerifyBlind.Enclave.Services;

/// <summary>
/// RegisterAsync akışında belirli bir adımda oluşan hatayı temsil eder.
/// Step property'si hangi adımda hata oluştuğunu tip-güvenli olarak belirtir.
/// </summary>
public class RegistrationException : Exception
{
    public RegistrationStep Step { get; }

    public RegistrationException(RegistrationStep step, string message, Exception? innerException = null)
        : base($"Registration failed at [{step}]: {message}", innerException)
    {
        Step = step;
    }
}

namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// libfido2's <c>fido_opt_t</c> (1.16.0, <c>fido/types.h</c>). <b>Not a C bool:</b> <see cref="Omit"/> (0) leaves the
/// key's default, which for user presence is on, so "off" is <see cref="False"/> (1). Every call that takes a
/// <c>fido_opt_t</c> takes this enum.
/// </summary>
public enum FidoOpt
{
    Omit = 0,
    False = 1,
    True = 2,
}

/// <summary>libfido2's constants tswap uses (1.16.0, <c>fido/param.h</c>): brief T19, Appendix B.</summary>
public static class Libfido2Params
{
    /// <summary><c>COSE_ES256</c>.</summary>
    public const int CoseEs256 = -7;

    /// <summary><c>FIDO_EXT_HMAC_SECRET</c>.</summary>
    public const int ExtHmacSecret = 0x01;

    /// <summary>Authenticator data flag: user present.</summary>
    public const byte FlagUserPresent = 0x01;

    /// <summary>Authenticator data flag: user verified.</summary>
    public const byte FlagUserVerified = 0x04;
}

/// <summary>libfido2's error codes tswap names (1.16.0, <c>fido/err.h</c>): brief T19, Appendix B.</summary>
public static class Libfido2Errors
{
    public const int Ok = 0x00;
    public const int ChannelBusy = 0x06;
    public const int UnsupportedExtension = 0x16;
    public const int CredentialExcluded = 0x19;
    public const int InvalidCredential = 0x22;
    public const int OperationDenied = 0x27;
    public const int UnsupportedOption = 0x2b;
    public const int KeepaliveCancel = 0x2d;
    public const int NoCredentials = 0x2e;
    public const int UserActionTimeout = 0x2f;
    public const int PinInvalid = 0x31;
    public const int PinBlocked = 0x32;
    public const int PinAuthInvalid = 0x33;
    public const int PinAuthBlocked = 0x34;
    public const int PinNotSet = 0x35;
    public const int PinRequired = 0x36;
    public const int PinPolicyViolation = 0x37;
    public const int ActionTimeout = 0x3a;
    public const int UpRequired = 0x3b;
    public const int UvBlocked = 0x3c;
    public const int Tx = -1;
    public const int Rx = -2;
    public const int RxNotCbor = -3;
    public const int RxInvalidCbor = -4;
    public const int InvalidArgument = -7;
    public const int UserPresenceRequired = -8;
    public const int Internal = -9;
    public const int NotFound = -10;

    /// <summary>
    /// The constant's name (<c>FIDO_OK</c>, <c>FIDO_ERR_CHANNEL_BUSY</c>, ...), or <c>FIDO_ERR_0x5d</c> for a code not
    /// listed (<c>FIDO_ERR_-11</c> for a negative one): what a <see cref="Fido2DeviceException"/>'s detail carries,
    /// never <c>fido_strerr</c>'s prose.
    /// </summary>
    public static string Name(int code) => code switch
    {
        Ok => "FIDO_OK",
        ChannelBusy => "FIDO_ERR_CHANNEL_BUSY",
        UnsupportedExtension => "FIDO_ERR_UNSUPPORTED_EXTENSION",
        CredentialExcluded => "FIDO_ERR_CREDENTIAL_EXCLUDED",
        InvalidCredential => "FIDO_ERR_INVALID_CREDENTIAL",
        OperationDenied => "FIDO_ERR_OPERATION_DENIED",
        UnsupportedOption => "FIDO_ERR_UNSUPPORTED_OPTION",
        KeepaliveCancel => "FIDO_ERR_KEEPALIVE_CANCEL",
        NoCredentials => "FIDO_ERR_NO_CREDENTIALS",
        UserActionTimeout => "FIDO_ERR_USER_ACTION_TIMEOUT",
        PinInvalid => "FIDO_ERR_PIN_INVALID",
        PinBlocked => "FIDO_ERR_PIN_BLOCKED",
        PinAuthInvalid => "FIDO_ERR_PIN_AUTH_INVALID",
        PinAuthBlocked => "FIDO_ERR_PIN_AUTH_BLOCKED",
        PinNotSet => "FIDO_ERR_PIN_NOT_SET",
        PinRequired => "FIDO_ERR_PIN_REQUIRED",
        PinPolicyViolation => "FIDO_ERR_PIN_POLICY_VIOLATION",
        ActionTimeout => "FIDO_ERR_ACTION_TIMEOUT",
        UpRequired => "FIDO_ERR_UP_REQUIRED",
        UvBlocked => "FIDO_ERR_UV_BLOCKED",
        Tx => "FIDO_ERR_TX",
        Rx => "FIDO_ERR_RX",
        RxNotCbor => "FIDO_ERR_RX_NOT_CBOR",
        RxInvalidCbor => "FIDO_ERR_RX_INVALID_CBOR",
        InvalidArgument => "FIDO_ERR_INVALID_ARGUMENT",
        UserPresenceRequired => "FIDO_ERR_USER_PRESENCE_REQUIRED",
        Internal => "FIDO_ERR_INTERNAL",
        NotFound => "FIDO_ERR_NOTFOUND",
        >= 0 => $"FIDO_ERR_0x{code:x2}",
        _ => $"FIDO_ERR_{code}",
    };
}

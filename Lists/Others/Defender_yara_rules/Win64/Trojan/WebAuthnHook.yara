rule Trojan_Win64_WebAuthnHook_MKV_2147975942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WebAuthnHook.MKV!MTB"
        threat_id = "2147975942"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WebAuthnHook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "g\\\\.\\pipe\\WebAuthnHook" ascii //weight: 5
        $x_5_2 = "WebAuthNAuthenticatorGetAssertion" ascii //weight: 5
        $x_4_3 = "SpecterOps.Passkeys.WebAuthnHook" ascii //weight: 4
        $x_3_4 = "webauthn.dll" ascii //weight: 3
        $x_3_5 = "inject" ascii //weight: 3
        $x_3_6 = "capture" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


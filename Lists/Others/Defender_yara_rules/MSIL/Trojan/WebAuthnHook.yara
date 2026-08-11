rule Trojan_MSIL_WebAuthnHook_MKZ_2147975943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebAuthnHook.MKZ!MTB"
        threat_id = "2147975943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebAuthnHook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "CreateRemoteThread" ascii //weight: 4
        $x_4_2 = "OpenProcess" ascii //weight: 4
        $x_4_3 = "VirtualAllocEx" ascii //weight: 4
        $x_4_4 = "WriteProcessMemory" ascii //weight: 4
        $x_4_5 = "WebAuthnHook_x64.dll" ascii //weight: 4
        $x_4_6 = "WebAuthnHook_x86.dll" ascii //weight: 4
        $x_4_7 = "InjectIntoProcess" ascii //weight: 4
        $x_3_8 = "\\\\.\\pipe\\" ascii //weight: 3
        $x_3_9 = "payload" ascii //weight: 3
        $x_3_10 = "SharpPasskeys CLI" ascii //weight: 3
        $x_3_11 = "Pass-the-Passkey" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


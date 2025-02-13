rule HackTool_Win32_SharpZeroLogon_2147764484_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SharpZeroLogon"
        threat_id = "2147764484"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SharpZeroLogon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "SharpZeroLogon" ascii //weight: 8
        $x_2_2 = "31d6cfe0d16ae931b73c59d7e0c089c0" ascii //weight: 2
        $x_1_3 = {b8 01 00 00 00 83 f8 01 75 3b}  //weight: 1, accuracy: High
        $x_1_4 = "logoncli.dll" ascii //weight: 1
        $x_1_5 = "netapi32.dll" ascii //weight: 1
        $x_1_6 = "I_NetServerReqChallenge" ascii //weight: 1
        $x_1_7 = "I_NetServerAuthenticate2" ascii //weight: 1
        $x_1_8 = "I_NetServerPasswordSet2" ascii //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "GetModuleInformation" ascii //weight: 1
        $x_1_12 = "NL_TRUST_PASSWORD" ascii //weight: 1
        $x_1_13 = "NETLOGON_AUTHENTICATOR" ascii //weight: 1
        $x_1_14 = "ClearNewPassword" ascii //weight: 1
        $x_1_15 = "NETLOGON_SECURE_CHANNEL_TYPE" ascii //weight: 1
        $x_1_16 = "NETLOGON_CREDENTIAL" ascii //weight: 1
        $x_1_17 = "ClientChallenge" ascii //weight: 1
        $x_1_18 = "ServerChallenge" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_1_*))) or
            ((1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_8_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


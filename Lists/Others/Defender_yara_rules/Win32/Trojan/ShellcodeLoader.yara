rule Trojan_Win32_ShellcodeLoader_A_2147917888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeLoader.A!MTB"
        threat_id = "2147917888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 45 f0 48 8b 45 f0 48 81 c4 d0 00 00 00 5d c3 55 48 81 ec 60 02 00 00 48 8d ac 24 80 00 00 00 48 89 8d f0 01 00 00 48 89 95 f8 01 00 00 4c 89 85 00 02 00 00 4c 89 8d 08 02 00 00 48 c7 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeLoader_MRZ_2147946840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeLoader.MRZ!MTB"
        threat_id = "2147946840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 0f b6 94 8d ?? ?? ?? ?? 88 55 ea 8b 55 f0 0f b6 4d ea 30 0c 32 46 ff 4d e4 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeLoader_AHD_2147959478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeLoader.AHD!MTB"
        threat_id = "2147959478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ExecuteShellcodePayload" ascii //weight: 10
        $x_20_2 = "DecryptAndExtractPayload" ascii //weight: 20
        $x_30_3 = "PayloadThread" ascii //weight: 30
        $x_40_4 = {66 c7 44 24 47 74 75 c6 44 24 49 61 88 54 24 4a c6 44 24 4b 41 88 54 24 4c}  //weight: 40, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win32_Lasdumpz_A_2147808498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Lasdumpz.A!MTB"
        threat_id = "2147808498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lasdumpz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 60 48 8d ?? ?? 4c 89 74 24 58 45 33 c9 4c 89 74 24 50 45 33 c0 4c 89 74 24 48 33 d2 4c 89 74 24 40 4c 89 74 24 38 4c 89 74 24 30 48 89 44 24 28 48 8d ?? ?? 48 89 44 24 20 ff 15 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 8b 55 98 85 d2 0f 84 ?? ?? ?? ?? 81 7d 9c ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SECURITY\\Policy\\Secrets" ascii //weight: 1
        $x_1_3 = "GT__Decrypt" ascii //weight: 1
        $x_1_4 = {48 33 c4 48 89 85 20 02 00 00 45 33 f6 ba 08 02 00 00 44 89 75 98 41 8d ?? ?? ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? 41 b9 19 00 02 00 45 33 c0 48 89 44 24 20 48 8d ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Lasdumpz_B_2147937494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Lasdumpz.B!MTB"
        threat_id = "2147937494"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lasdumpz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 b8 ff 0f 0f 00 4c 89 7d ?? 48 8d 55 ?? c7 45 ?? 1a 00 1c 00}  //weight: 10, accuracy: Low
        $x_10_2 = "SECURITY\\Policy\\Secrets\\__GT__Decrypt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win32_Dragzxor_A_2147838158_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dragzxor.A!MTB"
        threat_id = "2147838158"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dragzxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b cb e8 ?? ?? ?? ?? 48 8b 43 30 4c 8d ?? ?? ?? ba 08 00 00 00 48 89 05 3b 49 02 00 48 8d ?? ?? 44 8d ?? ?? ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 43 30}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 0f 00 00 00 89 4c 24 32 66 89 44 24 30 4c 8d ?? ?? ?? 48 8b 07 48 8d ?? ?? ?? 66 89 4c 24 36 48 89 4c 24 38 48 8b cf c7 44 24 40 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b c8 33 d2 48 8b d8 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? 33 d2 48 8b cb 44 8d ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 54 24 10 48 89 4c 24 08 48 83 ec 38 48 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 48 8b 54 24 48 48 8b 4c 24 40 e8 ?? ?? ?? ?? 48 83 c4 38}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b c8 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 48 83 c4 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


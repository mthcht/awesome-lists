rule VirTool_Win64_Revshelesz_A_2147913712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Revshelesz.A!MTB"
        threat_id = "2147913712"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Revshelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 41 b8 06 00 00 00 ba 01 00 00 00 b9 02 00 00 00 ?? ?? ?? ?? ?? ?? 48 89 05 e8 f9 00 00 b8 02 00 00 00 66 89 05 e4 f9 00 00 0f b7 8d b4 03 00 00 ?? ?? ?? ?? ?? ?? 66 89 05 d2 f9 00 00 41 b9 38 00 00 00 [0-38] 48 89 85 b8 0f 00 00 48 8b 85 b8 0f 00 00 48 89 85 c0 0f 00 00 48 8b 8d c0 0f 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 05 84 f9 00 00 [0-18] 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 41 b8 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 0d 28 f9 00 00 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 00 00 00 00 c7 44 24 20 01 00 00 00 45 33 c9 45 33 c0 48 8b d0 33 c9 ?? ?? ?? ?? ?? ?? 89 85 44 0f 00 00 [0-18] 83 bd 44 0f 00 00 00 ?? ?? ba ff ff ff ff 48 8b 8d 98 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Blindz_A_2147838738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Blindz.A!MTB"
        threat_id = "2147838738"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Blindz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 10 68 00 00 00 41 b8 18 00 00 00 33 d2 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 8f 0a 87 06 e8 ?? ?? ?? ?? 48 89 85 c8 00 00 00 ba 71 91 32 37 48 8b 8d c8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b f8 33 c0 b9 d0 04 00 00 f3 aa c7 45 40 12 00 10 00 48 8b 85 50 0f 00 00 48 89 45 58 48 c7 85 80 00 00 00 01 00 00 00 48 8d ?? ?? 48 8b 8d 58 0f 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b f8 33 c0 b9 d0 04 00 00 f3 aa c7 85 00 06 00 00 1f 00 10 00 48 8d ?? ?? ?? ?? ?? 48 8b 8d 58 0f 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 63 45 24 48 8b 8d 20 01 00 00 0f be 04 01 03 45 04 8b 4d 04 8d ?? ?? 89 45 04 eb b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


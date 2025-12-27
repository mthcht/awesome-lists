rule VirTool_Win64_Diresz_A_2147958316_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Diresz.A"
        threat_id = "2147958316"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Diresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 c7 44 24 20 ?? ?? 00 00 45 33 c0 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b f8 e8 ?? ?? ?? ?? 8b d8 85 c0 ?? ?? 8b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b cf 48 89 74 24 48 45 33 c0 48 89 74 24 40 ba ff ff 1f 00 48 89 74 24 38 48 89 74 24 30 48 89 74 24 28 48 89 44 24 20 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b d1 b8 18 00 00 00 0f 05 c3 4c 8b d1 b8 c7 00 00 00 0f 05 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


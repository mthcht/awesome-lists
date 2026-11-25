rule VirTool_Win64_Treslesz_A_2147982770_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Treslesz.A"
        threat_id = "2147982770"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Treslesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 9c 24 c8 00 00 00 33 c9 48 89 b4 24 a8 00 00 00 48 8b 72 08 4c 89 b4 24 98 00 00 00 4c 8b 72 10 33 d2 4c 89 bc 24 ?? 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 4c 89 7c 24 40 45 33 c0 c7 44 24 38 02 00 00 00 ba ff ff ff ff 4c 89 7c 24 30 33 c9 c7 44 24 28 03 00 00 00 c7 44 24 20 05 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 4d 0f 48 85 c9 ?? ?? ?? ?? ?? ?? 4c 89 7d 07 ?? ?? ?? ?? 48 8b 01 ?? ?? ?? ?? ?? ?? ?? 4c 8b 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Reflenesz_A_2147976037_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Reflenesz.A"
        threat_id = "2147976037"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 41 59 31 c9 41 b8 00 30 00 00 ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? 66 c7 40 04 05 c3 c7 00 4c 8b d1 0f 48 89 [0-18] 48 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 51 30 44 8b 41 38 45 39 d0 45 0f 47 d0 44 8b 49 34 48 83 c1 28 48 83 c2 d8 41 39 c1 ?? ?? 45 01 ca 44 39 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Refledeiz_A_2147967987_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Refledeiz.A"
        threat_id = "2147967987"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Refledeiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 4d 03 fd 41 b9 40 00 00 00 41 b8 00 30 00 00 41 8b 57 50 ff ?? 41 8b 57 50 48 8b c8 4c 8b f0 ff ?? 41 8b 57 54 49 8b cd 48 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 01 41 88 04 08 ?? ?? ?? ?? 48 83 ea 01 ?? ?? 45 0f b7 57 06 41 0f b7 47 14 4d 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


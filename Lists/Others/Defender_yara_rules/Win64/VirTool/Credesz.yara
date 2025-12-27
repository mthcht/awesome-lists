rule VirTool_Win64_Credesz_A_2147958318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credesz.A"
        threat_id = "2147958318"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c3 49 8b d6 e8 [0-17] 48 39 44 24 60 [0-16] c7 44 24 68 01 00 00 00 41 b9 04 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? 48 8b d6 48 8b cf ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 41 b9 04 00 00 00 89 5d ?? ?? ?? ?? ?? 48 89 44 24 20 49 8b d6 48 8b cf ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 83 7d a0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


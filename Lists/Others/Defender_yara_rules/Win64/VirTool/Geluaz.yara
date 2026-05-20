rule VirTool_Win64_Geluaz_A_2147969783_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geluaz.A"
        threat_id = "2147969783"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geluaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 48 8b f1 49 8b d8 48 8b ca 48 8b fa e8 ?? ?? ?? ?? 4c 8b cb 4c 8b c0 48 8b d7 48 8b ce e8}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b cf 45 33 c0 33 d2 48 8b ce e8 ?? ?? ?? ?? 33 d2 b9 02 00 00 00 8b d8 e8 ?? ?? ?? ?? 8b d7 48 8b ce e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Kilebesz_A_2147965884_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kilebesz.A"
        threat_id = "2147965884"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kilebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 08 55 53 56 57 41 55 ?? ?? ?? ?? ?? 48 81 ec c0 00 00 00 b9 20 00 00 00 49 8b f0 48 8b da e8 ?? ?? ?? ?? 48 8b f8 45 33 ed ?? ?? ?? ?? ?? ?? ?? 48 8b cf 48 89 07}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 41 04 48 8b 4c 30 48 48 8b 01 41 b8 21 00 00 00 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? 48 83 f8 21 ?? ?? ba 04 00 00 00 8b fa 89 54 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


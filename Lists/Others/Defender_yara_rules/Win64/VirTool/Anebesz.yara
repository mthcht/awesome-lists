rule VirTool_Win64_Anebesz_A_2147958743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Anebesz.A"
        threat_id = "2147958743"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Anebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 68 48 39 44 24 50 ?? ?? ?? ?? ?? ?? 48 63 44 24 34 48 8b 4c 24 38 0f b7 04 41 3d 00 d8 00 00 ?? ?? ?? ?? ?? ?? 48 63 44 24 34 48 8b 4c 24 38 0f b7 04 41 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 44 05 ff 00 00 00 39 44 24 4c ?? ?? 8b 44 24 44 8b 4c 24 4c 2b c8 8b c1 48 8b 4c 24 50 48 8b 54 24 70 48 03 d1 48 8b ca 88 01 48 8b 44 24 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


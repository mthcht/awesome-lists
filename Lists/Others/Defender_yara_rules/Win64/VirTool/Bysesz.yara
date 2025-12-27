rule VirTool_Win64_Bysesz_A_2147956756_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bysesz.A"
        threat_id = "2147956756"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bysesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b ce 49 8b c6 80 3c 07 b8 ?? ?? 83 f9 1c ?? ?? ff c1 48 ff c0 48 83 f8 20 ?? ?? 41 8b d6}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 8d b0 06 00 00 [0-20] 48 89 44 24 20 ?? ?? ?? ?? ?? ?? ?? 66 41 c7 06 ?? e9 48 c7 c1 ff ff ff ff 45 88 7e 02 45 88 66 03 45 88 6e 04 41 88 76 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


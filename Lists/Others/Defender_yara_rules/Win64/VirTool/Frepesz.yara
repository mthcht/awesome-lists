rule VirTool_Win64_Frepesz_A_2147976420_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Frepesz.A"
        threat_id = "2147976420"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Frepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b d5 c7 44 24 38 00 00 00 00 ?? ?? ?? ?? ?? 41 b8 04 00 00 00 48 8b cd ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b 44 24 38 8b fb 49 03 ff 41 89 46 14 81 fe 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 04 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 33 c9 ff ?? ?? ?? ?? ?? ba 5c 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ff [0-19] ba 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Virgesz_A_2147962850_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Virgesz.A"
        threat_id = "2147962850"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Virgesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 03 49 89 53 08 48 89 ?? ?? ?? ?? ?? 48 83 3d 0b 36 49 00 00 ?? ?? 48 8b [0-18] b9 0c 03 00 00 e8 ?? ?? ?? ?? 48 85 ff ?? ?? 31 db 31 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 ec 30 48 8b 42 08 48 89 44 24 28 ?? bb 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? bf 1b 00 00 00 31 f6 e8 ?? ?? ?? ?? 48 8b 44 24 28 e8 ?? ?? ?? ?? 48 83 c4 30 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_HBPAmsibyp_A_2147941248_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HBPAmsibyp.A"
        threat_id = "2147941248"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HBPAmsibyp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 01 48 8b f1 bd 01 00 00 00 81 38 04 00 00 80}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 83 98 00 00 00 48 8b 50 30 ?? ?? ?? ?? ?? ?? ?? c7 02 00 00 00 00 81 4b 44 00 00 01 00 48 89 83 f8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


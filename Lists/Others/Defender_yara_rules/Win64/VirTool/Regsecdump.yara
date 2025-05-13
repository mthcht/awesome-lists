rule VirTool_Win64_Regsecdump_A_2147941245_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Regsecdump.A"
        threat_id = "2147941245"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Regsecdump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 5c 00 4c 00 53 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 53 00 65 00 63 00 72 00 65 00 74 00 73 00 5c 00 44 00 50 00 41 00 50 00 49 00 5f 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 56 00 61 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = {8a 01 3a 04 11 ?? ?? 48 ff c1 49 ff c8 ?? ?? 48 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


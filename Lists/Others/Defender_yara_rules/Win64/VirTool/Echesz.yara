rule VirTool_Win64_Echesz_A_2147973194_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Echesz.A"
        threat_id = "2147973194"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Echesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 48 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 46 08 41 b9 00 30 00 00 31 d2 48 89 d9 c7 44 24 20 04 00 00 00 ?? ?? ?? ?? 49 89 f8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c5 48 85 c0 ?? ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 49 89 f9 4c 8b 06 48 89 c2 48 89 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {49 89 c1 48 85 c0 ?? ?? c7 44 24 28 00 00 00 00 45 31 c0 31 d2 48 89 d9 48 c7 44 24 30 00 00 00 00 48 89 6c 24 20 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


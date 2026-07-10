rule VirTool_Win64_Flekesz_A_2147973274_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Flekesz.A"
        threat_id = "2147973274"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Flekesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 08 48 89 c3 b9 01 00 00 00 48 89 cf 48 8b 44 24 38 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 58 ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 60 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 40 49 89 0b 48 89 44 24 38 48 89 48 18 48 c7 40 10 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 48 08 48 c7 44 24 68 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 70 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 40 48 c7 40 18 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Vekesz_A_2147966449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vekesz.A"
        threat_id = "2147966449"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vekesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 4d d0 4c 89 45 d8 48 89 45 e0 ?? ?? ?? ?? ?? ?? ?? 48 89 45 e8 48 89 4d f0 48 89 45 f8 48 89 55 00 48 89 45 08 48 89 7d 10}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 01 6a 02 58 48 89 41 08 48 83 61 20 00 ?? ?? ?? ?? ?? ?? ?? 48 89 95 58 0e 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 51 10 48 89 41 18}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 f1 e8 ?? ?? ?? ?? c6 86 54 02 00 00 02 ?? ?? ?? ?? ?? ?? ?? ?? b9 58 02 00 00 48 89 d7}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 f1 48 89 da e8 [0-24] 48 89 02 ?? ?? ?? ?? ?? ?? ?? 48 89 42 08 48 89 72 10 ?? ?? ?? ?? ?? ?? ?? 48 89 42 18}  //weight: 1, accuracy: Low
        $x_1_5 = {49 89 47 08 4d 89 47 10 49 89 47 18 ?? ?? ?? ?? ?? ?? ?? 4c 89 fa e8 ?? ?? ?? ?? 48 89 74 24 40 ?? ?? ?? ?? 48 89 44 24 48 48 83 c7 ?? 4d 6b f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


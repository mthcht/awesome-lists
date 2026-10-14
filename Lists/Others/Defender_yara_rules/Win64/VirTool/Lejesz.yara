rule VirTool_Win64_Lejesz_A_2147980263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Lejesz.A"
        threat_id = "2147980263"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lejesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 f9 4c 89 f2 41 b8 a8 73 4f ee e8 ?? ?? ?? ?? 66 41 83 7f 04 00 b8 00 00 00 00 ?? ?? 8b 84 24 ?? 01 00 00 89 05 [0-19] 4c 89 f9 4c 89 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 21 41 58 48 8b 9d 50 19 00 00 48 89 d9 e8 ?? ?? ?? ?? c7 85 20 18 00 00 00 00 ff e0 48 c7 85 18 18 00 00 48 b8 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


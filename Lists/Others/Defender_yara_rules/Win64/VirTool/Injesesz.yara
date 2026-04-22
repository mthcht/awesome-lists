rule VirTool_Win64_Injesesz_A_2147967495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injesesz.A"
        threat_id = "2147967495"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injesesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 45 31 c9 59 48 89 f2 45 31 c0 49 96 e8 [0-17] 49 97 ff ?? ?? ?? ?? ?? ?? ?? ?? ff ?? 83 c9 ff ff ?? 4c 89 f9 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 48 c7 44 24 30 50 01 00 00 48 89 44 24 38 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 41 89 c8 ff ?? 41 83 e0 07 47 8a 04 01 44 30 00 48 ff c0 81 f9 50 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 f2 48 c7 44 24 40 ?? ?? ?? ?? 31 c9 48 89 44 24 50 48 83 64 24 48 00 6a 02 41 58 e8 [0-17] 48 96 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


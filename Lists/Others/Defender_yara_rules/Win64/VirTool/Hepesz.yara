rule VirTool_Win64_Hepesz_A_2147969160_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hepesz.A"
        threat_id = "2147969160"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4d b0 48 c7 45 f0 01 00 00 00 c7 45 ec 00 00 00 00 ?? ?? ?? ?? 48 89 74 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 48 c7 c1 ff ff ff ff 41 b9 20 01 00 00 ff ?? ?? ?? ?? ?? 89 45 e8 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 f1 e8 ?? ?? ?? ?? 48 c7 84 24 d0 ?? ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 66 ?? 31 c9 48 89 f2 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 2c 81 fa 04 00 00 80 ?? ?? ?? ?? ?? ?? 81 fa 01 00 00 80 ?? ?? ?? ?? ?? ?? 48 8b 76 08 48 39 4d c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


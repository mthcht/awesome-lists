rule VirTool_Win64_Enkelesz_A_2147962848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Enkelesz.A"
        threat_id = "2147962848"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Enkelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b da 48 8b f9 39 35 [0-19] e8 [0-17] 4c 8b c3 48 8b d7 e8 ?? ?? ?? ?? 48 8b 8f 18 29 19 00 ff ?? ?? ?? ?? ?? 39 35}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 60 4c 8b b2 b8 00 00 00 4c 8b 69 40 8b 0d ?? ?? ?? ?? 48 8b 72 18 45 8b 66 10 41 8b 6e 08 45 33 ff 48 8b fa 41 3b cf 41 8b df}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b da 48 8b f9 [0-18] 41 b8 68 00 00 00 e8 ?? ?? ?? ?? 33 ed 39 2d ?? ?? ?? ?? 48 89 6c 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


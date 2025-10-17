rule VirTool_Win64_Asmldr_A_2147955394_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Asmldr.A"
        threat_id = "2147955394"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Asmldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 33 db 4d 33 e4 44 8b 60 3c 4c 03 e0 49 81 c4 08 01 00 00 45 8b 5c 24 08 44 89 19 4d 33 db 45 8b 5c 24 0c 49 03 c3 c3}  //weight: 1, accuracy: High
        $x_1_2 = {50 41 50 52 48 8b 0d ?? 21 00 00 48 8b d0 e8 ?? ?? ?? ?? 48 85 c0 5a 41 58 58 74 ?? 66 ff c3 49 3b c0 75 ?? 48 0f b7 c3 66 b9 5a 00 66 3b d9 7d ?? c3 48 c7 c0 ff ff 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


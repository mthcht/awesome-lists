rule TrojanDropper_Win32_Bewmecky_A_2147626862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bewmecky.A"
        threat_id = "2147626862"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewmecky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 79 fd 2e 75 17 80 79 fe 65 75 11 80 79 ff 78 75 0b 80 39 65 75 06}  //weight: 1, accuracy: High
        $x_1_2 = {50 ff 75 08 ff 15 ?? ?? ?? ?? ff 75 e0 e8 ?? ?? ?? ?? 59 8b 4d e0 80 7c 08 fb 32 74 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d3 6a 02 59 3b c1 74 17 8d 56 f8 ff 75 e4 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


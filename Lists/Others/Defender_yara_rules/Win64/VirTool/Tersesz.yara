rule VirTool_Win64_Tersesz_A_2147981494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Tersesz.A"
        threat_id = "2147981494"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tersesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 29 85 b0 06 00 00 0f 29 85 a0 06 00 00 48 8b 8d a0 08 00 00 48 89 7c 24 20 [0-20] 41 b8 56 01 00 00 4d 89 f1 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 6c 24 20 48 89 d9 4c 89 fa 49 89 f8 41 b9 40 00 00 00 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 bd 48 09 00 00 4c 89 b5 50 09 00 00 4c 89 bd 58 09 00 00 [0-20] e8 ?? ?? ?? ?? ?? 48 83 c6 0f 48 89 b5 c8 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 f9 48 89 da ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


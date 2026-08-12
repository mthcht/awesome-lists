rule VirTool_Win64_Scerpesz_A_2147976038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Scerpesz.A"
        threat_id = "2147976038"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Scerpesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 68 45 33 c9 66 41 b8 ?? 1f ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 68 ff ?? ?? ?? ?? ?? 48 89 44 24 60 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 [0-20] 48 8b 4c 24 60 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 01 00 00 00 48 8b 8c 24 e8 00 00 00 ff [0-18] e8 ?? ?? ?? ?? 89 44 24 50 44 8b 44 24 50 33 d2 b9 ff ff 1f 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Segesz_A_2147982446_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Segesz.A"
        threat_id = "2147982446"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Segesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 02 00 00 00 66 89 44 24 32 ff ?? ?? ?? ?? ?? 48 8b 16 4c 8b 46 08 45 31 c9 48 8b 0b c7 44 24 28 10 00 00 00 41 29 d0 48 89 7c 24 20 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 02 02 00 00 ff ?? ?? ?? ?? ?? 85 c0 b8 00 00 00 00 ?? ?? 41 b8 11 00 00 00 ba 02 00 00 00 b9 02 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 05 00 00 00 [0-18] e8 ?? ?? ?? ?? 48 8b 4c 24 40 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 bd fe ff ff ff ff ff ff 7f 48 89 c6 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


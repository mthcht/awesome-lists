rule VirTool_Win64_Copotesz_A_2147978287_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Copotesz.A"
        threat_id = "2147978287"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Copotesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d8 48 85 c0 ?? ?? 41 b8 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 ff ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 ?? ?? 45 33 c0 33 d2 48 8b c8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b fa 4c 8b f1 45 33 e4 ?? ?? ?? ?? ?? ?? ?? 4c 89 64 24 38 41 b9 ff 00 00 00 c7 44 24 30 ff ff ff ff 45 33 c0 c7 44 24 28 00 02 00 00 ba 03 00 00 00 c7 44 24 20 00 02 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b cf ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff ?? ?? ?? ?? ?? 8b d0 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Dikesz_A_2147958317_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dikesz.A"
        threat_id = "2147958317"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dikesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 44 24 48 48 8b 54 24 50 48 8b 4c 24 58 e8 ?? ?? ?? ?? 85 c0 ?? ?? b8 ff ff ff ff ?? ?? 48 8b 44 24 28 81 38 4c 8b d1 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 54 24 30 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 b8 10 01 00 00 ?? ?? ?? ?? ?? 48 8b 4c 24 30 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 40 00 00 00 ba 10 01 00 00 48 8b 4c 24 30 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

